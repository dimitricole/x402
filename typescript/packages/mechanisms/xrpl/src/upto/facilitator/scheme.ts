import {
  CANONICAL_SIGNING_PUB_KEY_PATTERN,
  LANDING_MARGIN_SECONDS,
  RIPPLE_EPOCH_OFFSET,
  XRPL_CAIP_FAMILY,
} from "../../constants";
import { SettlementCache } from "../../settlement-cache";
import {
  decodeSignedTransactionBlob,
  getCurrentLedgerIndex,
  getLedgerCloseTime,
  getMaxSettlementLastLedgerSequence,
  getSettlementTtlMs,
  getPayChannel,
  getUptoXrplPayload,
  getXrplAccountAuthorization,
  isNonNegativeInteger,
  isRecord,
  isXrplNetwork,
  parseDrops,
  parseXrplNetworkId,
  submitSignedTransaction,
} from "../../utils";
import type { PayChannelEntry, UptoXrplPayload, XrplFacilitatorOptions } from "../../types";
import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
  SchemeNetworkFacilitator,
  SettleResponse,
  VerifyResponse,
} from "@x402/core/types";
import {
  PaymentChannelClaimFlags,
  deriveAddress,
  dropsToXrp,
  verifyPaymentChannelClaim,
  verifySignature,
  xrpToDrops,
  type PaymentChannelClaim,
  type TransactionMetadata,
} from "xrpl";

/**
 * XRPL facilitator implementation for the upto payment scheme.
 */
export class UptoXrplScheme implements SchemeNetworkFacilitator {
  readonly caipFamily = XRPL_CAIP_FAMILY;
  readonly scheme = "upto";
  private readonly options: XrplFacilitatorOptions;
  private readonly settlementCache: SettlementCache;

  /**
   * Creates a new XRPL upto facilitator scheme.
   *
   * @param options - Facilitator configuration
   * @param settlementCache - Optional shared settlement cache; a private one is created by default
   */
  constructor(options: XrplFacilitatorOptions = {}, settlementCache?: SettlementCache) {
    this.options = options;
    this.settlementCache = settlementCache ?? new SettlementCache();
  }

  /**
   * Gets XRPL mechanism-specific supported metadata.
   *
   * @param _network - Network identifier
   * @returns Extra metadata advertising that fees are never sponsored
   */
  getExtra(_network: Network): Record<string, unknown> | undefined {
    return { areFeesSponsored: false };
  }

  /**
   * Gets XRPL facilitator signer addresses.
   *
   * @param _network - Network identifier
   * @returns Empty signer list because settlement submits the payTo-signed claim
   */
  getSigners(_network: string): string[] {
    return [];
  }

  /**
   * Verifies that a channel authorizes exactly the required amount.
   *
   * At verify time `requirements.amount` carries the authorized **maximum**.
   *
   * @param payload - Payment payload
   * @param requirements - Payment requirements
   * @returns Verification response
   */
  async verify(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<VerifyResponse> {
    return this.verifyPayment(payload, requirements, "verify");
  }

  /**
   * Settles the actual consumed amount by submitting the payTo-signed claim.
   *
   * At settle time `requirements.amount` carries the **actual** amount and
   * `payload.settlementTransaction` carries the hex blob of the
   * `PaymentChannelClaim` signed by the `payTo` account.
   *
   * @param payload - Payment payload
   * @param requirements - Payment requirements, with amount set to the actual charge
   * @returns Settlement response
   */
  async settle(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<SettleResponse> {
    // Never echo the envelope's network: a non-string one would produce a
    // response the resource server's own client rejects, losing the reason.
    let network = "" as Network;
    let payer = "";
    try {
      if (typeof requirements?.network === "string") {
        network = requirements.network;
      }
      const uptoPayload = getUptoXrplPayload(payload);
      if (!uptoPayload) {
        return failedSettle("invalid_upto_xrpl_payload", network, payer);
      }
      payer = uptoPayload.payer;

      const settleAmount = parseDrops(requirements.amount);
      if (settleAmount === undefined) {
        return failedSettle("invalid_upto_xrpl_settlement_amount", network, payer);
      }

      // Re-verification must run against the authorized maximum, not the
      // actual charge.
      const channelState: { channel?: PayChannelEntry } = {};
      const verification = await this.verifyPayment(
        payload,
        { ...requirements, amount: uptoPayload.maxAmount },
        "settle",
        channelState,
      );
      if (!verification.isValid) {
        return failedSettle(
          verification.invalidReason ?? "verification_failed",
          network,
          verification.payer ?? "",
          "",
          verification.invalidMessage,
        );
      }
      payer = verification.payer ?? "";

      if (settleAmount > BigInt(uptoPayload.maxAmount)) {
        return failedSettle("invalid_upto_xrpl_payload_settlement_exceeds_amount", network, payer);
      }

      const settlementBlob = uptoPayload.settlementTransaction;
      if (typeof settlementBlob !== "string" || settlementBlob === "") {
        return failedSettle("invalid_upto_xrpl_missing_settlement_transaction", network, payer);
      }
      // The source can raise the channel's Balance unilaterally, so a charge
      // it already covers cannot be expressed as a claim (a claim's Balance
      // must exceed the delivered total): like a zero settlement, it is a
      // bare destination close, which refunds only the undrawn remainder.
      const delivered = parseDrops(channelState.channel?.Balance);
      if (delivered === undefined) {
        return failedSettle("invalid_upto_xrpl_facilitator_error", network, payer);
      }
      const bareClose = settleAmount === 0n || delivered >= settleAmount;
      // A non-integer clock would defeat every window comparison below and
      // give the dedup entry a NaN expiry, which never prunes.
      const currentLedgerIndex = await getCurrentLedgerIndex(requirements.network, this.options);
      if (!isNonNegativeInteger(currentLedgerIndex)) {
        return failedSettle("invalid_upto_xrpl_facilitator_error", network, payer);
      }
      const claimCheck = this.verifySettlementTransaction(
        settlementBlob,
        uptoPayload,
        requirements,
        settleAmount,
        bareClose,
        currentLedgerIndex,
      );
      if ("reason" in claimCheck) {
        return failedSettle(claimCheck.reason, network, payer, "", claimCheck.message);
      }
      const signerError = await this.verifySettlementSigner(claimCheck.signingPubKey, requirements);
      if (signerError) {
        return failedSettle(signerError, network, payer);
      }

      // The channel is the settlement identity: it can only be drawn once. The
      // key carries the network because channel ids derive from (account,
      // sequence) and are identical across networks.
      const settlementTtlMs = getSettlementTtlMs(currentLedgerIndex, claimCheck.lastLedgerSequence);
      const settlementKey = `${requirements.network}:${uptoPayload.channelId.toUpperCase()}`;
      const settlementToken = this.settlementCache.acquire(settlementKey, settlementTtlMs);
      if (settlementToken === undefined) {
        return failedSettle("duplicate_settlement", network, payer);
      }

      try {
        const result = await submitSignedTransaction(
          settlementBlob,
          requirements.network,
          this.options,
        );
        if (!result.validated || result.resultCode !== "tesSUCCESS") {
          // Only a validated rejection is definitive; anything else may
          // still land.
          if (result.validated) {
            this.settlementCache.release(settlementKey, settlementToken);
          }
          return failedSettle(
            `transaction_failed: ${result.resultCode}`,
            network,
            payer,
            result.hash,
          );
        }
        // A claim applied to a channel that expired first closes it without
        // delivering and still returns tesSUCCESS, so the result code alone
        // is not evidence of payment: confirm the delivered amount from the
        // transaction metadata when the submission path provides it. For a
        // bare close the evidence is the settle-time validated Balance read
        // instead: the charge was delivered before submission, so the closing
        // transaction legitimately delivers nothing. Balance is monotonic, so
        // a final balance at or above the charge means the destination holds
        // the funds even when the source delivered them past our own read.
        const settledBalance = getFinalChannelBalance(result.meta, uptoPayload.channelId);
        if (!bareClose && settledBalance !== undefined && settledBalance < settleAmount) {
          return failedSettle(
            "transaction_failed: channel_expired_before_claim",
            network,
            payer,
            result.hash,
            `claim validated without delivering: channel balance ${settledBalance}, settlement ${settleAmount}`,
          );
        }
        return {
          success: true,
          transaction: result.hash,
          network,
          payer,
          amount: settleAmount.toString(),
        };
      } catch (error) {
        return failedSettle(
          `transaction_failed: ${error instanceof Error ? error.message : String(error)}`,
          network,
          payer,
        );
      }
    } catch (error) {
      return failedSettle(
        "invalid_upto_xrpl_facilitator_error",
        network,
        payer,
        "",
        error instanceof Error ? error.message : String(error),
      );
    }
  }

  /**
   * Verifies a payment for a given phase.
   *
   * Some channel rules are admission control: they decide whether the metered
   * work should begin, and are meaningless once it has. Re-applying them at
   * settlement would refuse claims the ledger accepts, handing the payer a
   * free-compute attack: it can invalidate them itself after receiving the
   * work. Settlement therefore asks only whether the claim can still land.
   *
   * @param payload - Payment payload
   * @param requirements - Payment requirements
   * @param phase - Whether this runs before the metered work or at settlement
   * @param channelOut - Receives the channel entry this verification read, so
   *   settlement decides the claim form from the same validated-ledger state
   * @param channelOut.channel - The channel entry, set once the read succeeds
   * @returns Verification response
   */
  private async verifyPayment(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
    phase: "verify" | "settle",
    channelOut?: { channel?: PayChannelEntry },
  ): Promise<VerifyResponse> {
    let payer = "";
    try {
      const envelopeError = this.verifyEnvelope(payload, requirements);
      if (envelopeError) {
        return invalidVerify(envelopeError, payer);
      }
      const requirementsCheck = verifyRequirements(requirements);
      if (typeof requirementsCheck === "string") {
        return invalidVerify(requirementsCheck, payer);
      }
      const requiredAmount = requirementsCheck;

      const uptoPayload = getUptoXrplPayload(payload);
      if (!uptoPayload) {
        return invalidVerify("invalid_upto_xrpl_payload", payer);
      }
      payer = uptoPayload.payer;

      // The settlement claim is server-owned and settle-time only: the
      // resource server's payload enrichment adds it after the metered work,
      // so a claim arriving at verification was supplied by the client.
      if (phase === "verify" && uptoPayload.settlementTransaction !== undefined) {
        return invalidVerify("invalid_upto_xrpl_payload_unexpected_settlement_transaction", payer);
      }

      // The claim verifier round-trips drops through an XRP float, where two
      // distinct amounts beyond 2^53 drops collide onto one signing message;
      // any amount the round trip does not preserve is rejected. The
      // conversion throws on extreme values instead of returning a mismatch.
      const maxAmount = parseDrops(uptoPayload.maxAmount);
      let maxAmountRoundTrips = false;
      try {
        maxAmountRoundTrips =
          xrpToDrops(dropsToXrp(uptoPayload.maxAmount)) === uptoPayload.maxAmount;
      } catch {
        maxAmountRoundTrips = false;
      }
      if (maxAmount === undefined || !maxAmountRoundTrips) {
        return invalidVerify("invalid_upto_xrpl_max_amount", payer);
      }

      const channel = await getPayChannel(
        uptoPayload.channelId,
        requirements.network,
        this.options,
      );
      if (!channel) {
        return invalidVerify("invalid_upto_xrpl_channel_not_found", payer);
      }
      if (channelOut) {
        channelOut.channel = channel;
      }

      const channelError = this.verifyChannelBinding(
        channel,
        uptoPayload,
        requirements,
        requiredAmount,
        maxAmount,
        phase,
      );
      if (channelError) {
        return invalidVerify(channelError, payer);
      }

      const timingError = await this.verifyChannelTiming(channel, requirements, phase);
      if (timingError) {
        return invalidVerify(timingError, payer);
      }

      return { isValid: true, payer };
    } catch (error) {
      return invalidVerify(
        "invalid_upto_xrpl_facilitator_error",
        payer,
        error instanceof Error ? error.message : String(error),
      );
    }
  }

  /**
   * Verifies the x402 envelope fields against the advertised requirements.
   *
   * @param payload - x402 payment payload
   * @param requirements - Payment requirements
   * @returns Invalid reason, if validation fails
   */
  private verifyEnvelope(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): string | undefined {
    if (payload.x402Version !== 2) {
      return "invalid_x402_version";
    }
    if (!isRecord(payload.accepted) || !isRecord(requirements)) {
      return "invalid_upto_xrpl_payload";
    }
    if (payload.accepted.scheme !== "upto" || requirements.scheme !== "upto") {
      return "unsupported_scheme";
    }
    if (!isXrplNetwork(requirements.network) || !isXrplNetwork(payload.accepted.network)) {
      return "invalid_network";
    }
    // `xrpl:01` and `xrpl:1` name one ledger, and the dedup key is built from
    // the string, so a non-canonical id would be a second lock on one channel.
    try {
      if (requirements.network !== `xrpl:${parseXrplNetworkId(requirements.network)}`) {
        return "invalid_network";
      }
    } catch {
      return "invalid_network";
    }
    if (payload.accepted.network !== requirements.network) {
      return "invalid_upto_xrpl_network_mismatch";
    }
    if (payload.accepted.asset !== requirements.asset) {
      return "invalid_upto_xrpl_asset_mismatch";
    }
    if (payload.accepted.amount !== requirements.amount) {
      return "invalid_upto_xrpl_amount_mismatch";
    }
    if (payload.accepted.payTo !== requirements.payTo) {
      return "invalid_upto_xrpl_pay_to_mismatch";
    }
    if (payload.accepted.maxTimeoutSeconds !== requirements.maxTimeoutSeconds) {
      return "invalid_upto_xrpl_max_timeout_mismatch";
    }
    if (
      requirements.extra?.areFeesSponsored !== false ||
      payload.accepted.extra?.areFeesSponsored !== false
    ) {
      return "invalid_upto_xrpl_fees_sponsored_unsupported";
    }
    // `extra` is opaque to core, so an absent optional may arrive as either
    // null or undefined depending on the implementation that sent it.
    const minSettleDelay = optional(requirements.extra?.minSettleDelay);
    const validAfter = optional(requirements.extra?.validAfter);
    if (optional(payload.accepted.extra?.minSettleDelay) !== minSettleDelay) {
      return "invalid_upto_xrpl_min_settle_delay_mismatch";
    }
    if (optional(payload.accepted.extra?.validAfter) !== validAfter) {
      return "invalid_upto_xrpl_valid_after_mismatch";
    }
    return undefined;
  }

  /**
   * Verifies the channel's bindings, amounts and the payer's claim signature.
   *
   * @param channel - PayChannel ledger entry
   * @param uptoPayload - XRPL upto payload
   * @param requirements - Payment requirements
   * @param requiredAmount - Required amount in drops
   * @param maxAmount - Authorized maximum in drops
   * @param phase - Whether this runs before the metered work or at settlement
   * @returns Invalid reason, if validation fails
   */
  private verifyChannelBinding(
    channel: PayChannelEntry,
    uptoPayload: UptoXrplPayload,
    requirements: PaymentRequirements,
    requiredAmount: bigint,
    maxAmount: bigint,
    phase: "verify" | "settle",
  ): string | undefined {
    // A user-supplied getPayChannel is not bound by PayChannelEntry at runtime.
    if (
      parseDrops(channel.Amount) === undefined ||
      parseDrops(channel.Balance) === undefined ||
      !isNonNegativeInteger(channel.SettleDelay) ||
      (channel.CancelAfter !== undefined && !isNonNegativeInteger(channel.CancelAfter)) ||
      (channel.Expiration !== undefined && !isNonNegativeInteger(channel.Expiration))
    ) {
      return "invalid_upto_xrpl_channel_malformed";
    }
    if (channel.Destination !== requirements.payTo) {
      return "invalid_upto_xrpl_destination_mismatch";
    }
    if (channel.Account !== uptoPayload.payer) {
      return "invalid_upto_xrpl_payer_mismatch";
    }
    // Equality, not >=: settle() re-verifies with requirements.amount set to
    // maxAmount, so an over-authorized payload would never be settleable.
    if (maxAmount !== requiredAmount) {
      return "invalid_upto_xrpl_max_amount_mismatch";
    }
    if (maxAmount > BigInt(channel.Amount)) {
      return "invalid_upto_xrpl_authorization_exceeds_channel";
    }
    if (channel.PublicKey.toUpperCase() !== uptoPayload.publicKey.toUpperCase()) {
      return "invalid_upto_xrpl_public_key_mismatch";
    }

    // Unit asymmetry in xrpl.js, silent when wrong: `authorizeChannel` signs
    // over the amount in DROPS, while `verifyPaymentChannelClaim` takes XRP
    // and applies xrpToDrops itself. The call also throws on malformed
    // signature hex rather than returning false.
    let claimSignatureValid: boolean;
    try {
      claimSignatureValid = verifyPaymentChannelClaim(
        uptoPayload.channelId,
        dropsToXrp(uptoPayload.maxAmount).toString(),
        uptoPayload.signature,
        uptoPayload.publicKey,
      );
    } catch {
      claimSignatureValid = false;
    }
    if (!claimSignatureValid) {
      return "invalid_upto_xrpl_claim_signature";
    }

    // Single use, before the work begins. At settlement any Balance is
    // acceptable: the source can deliver drops unilaterally at any time, so a
    // nonzero Balance below the charge only pre-pays part of the bill (the
    // claim delivers the difference), and one at or above it means the charge
    // is already delivered and settlement is a bare close. Refusing over
    // either would strand a payment the ledger can still settle.
    if (phase === "verify" && parseDrops(channel.Balance) !== 0n) {
      return "invalid_upto_xrpl_channel_already_drawn";
    }
    return undefined;
  }

  /**
   * Verifies the channel's time bounds against the validated ledger clock.
   *
   * @param channel - PayChannel ledger entry
   * @param requirements - Payment requirements
   * @param phase - Whether this runs before the metered work or at settlement
   * @returns Invalid reason, if validation fails
   */
  private async verifyChannelTiming(
    channel: PayChannelEntry,
    requirements: PaymentRequirements,
    phase: "verify" | "settle",
  ): Promise<string | undefined> {
    if (channel.CancelAfter === undefined) {
      return "invalid_upto_xrpl_missing_time_bound";
    }
    const ledgerCloseTime = await getLedgerCloseTime(requirements.network, this.options);
    if (!isNonNegativeInteger(ledgerCloseTime)) {
      return "invalid_upto_xrpl_facilitator_error";
    }
    // The margin covers the ledgers a claim takes to land, at both phases: a
    // channel admitted at verify must still be settleable after the work.
    // Inclusive bound, so that verify's admission bound (at least the work
    // plus one margin remaining) still holds here when the work consumed its
    // full budget.
    if (channel.CancelAfter < ledgerCloseTime + LANDING_MARGIN_SECONDS) {
      return "invalid_upto_xrpl_channel_expired";
    }
    // A source-initiated close only takes effect once Expiration passes, and
    // SettleDelay is what guarantees the destination time to claim before it
    // does; a pending close is therefore not itself a reason to refuse.
    if (
      channel.Expiration !== undefined &&
      channel.Expiration < ledgerCloseTime + LANDING_MARGIN_SECONDS
    ) {
      return "invalid_upto_xrpl_channel_expired";
    }
    if (phase === "verify") {
      // Admission must imply settleability: the channel has to outlive the
      // metered work *and* the landing that follows it.
      if (
        channel.CancelAfter - ledgerCloseTime <
        requirements.maxTimeoutSeconds + LANDING_MARGIN_SECONDS
      ) {
        return "invalid_upto_xrpl_insufficient_time_bound";
      }
      // A close requested the moment the work starts must still leave the
      // destination time to land its claim.
      if (channel.SettleDelay < LANDING_MARGIN_SECONDS) {
        return "invalid_upto_xrpl_settle_delay_too_short";
      }
      // Admission-only: SettleDelay is fixed at PaymentChannelCreate, so it
      // cannot have changed since admission.
      const minSettleDelay = requirements.extra?.minSettleDelay;
      if (typeof minSettleDelay === "number" && channel.SettleDelay < minSettleDelay) {
        return "invalid_upto_xrpl_settle_delay_too_short";
      }
      if (channel.Expiration !== undefined) {
        return "invalid_upto_xrpl_channel_closing";
      }
      const validAfter = requirements.extra?.validAfter;
      if (typeof validAfter === "number" && ledgerCloseTime + RIPPLE_EPOCH_OFFSET < validAfter) {
        return "invalid_upto_xrpl_not_yet_valid";
      }
    }
    return undefined;
  }

  /**
   * Verifies the payTo-signed settlement transaction against the payment.
   *
   * @param settlementBlob - Hex-encoded signed PaymentChannelClaim blob
   * @param uptoPayload - XRPL upto payload
   * @param requirements - Payment requirements
   * @param settleAmount - Actual settlement amount in drops
   * @param bareClose - Whether the settlement must be a bare destination
   *   close: a zero charge, or one the channel's Balance already covers
   * @param currentLedgerIndex - Current validated ledger index
   * @returns The blob's signing key and ledger window, else a reason and detail
   */
  private verifySettlementTransaction(
    settlementBlob: string,
    uptoPayload: UptoXrplPayload,
    requirements: PaymentRequirements,
    settleAmount: bigint,
    bareClose: boolean,
    currentLedgerIndex: number,
  ): { signingPubKey: string; lastLedgerSequence: number } | { reason: string; message: string } {
    const mismatch = (message: string): { reason: string; message: string } => ({
      reason: "invalid_upto_xrpl_settlement_transaction_mismatch",
      message,
    });

    let claim: PaymentChannelClaim;
    try {
      const decoded = decodeSignedTransactionBlob(settlementBlob);
      if (decoded.TransactionType !== "PaymentChannelClaim") {
        return mismatch("not a PaymentChannelClaim");
      }
      claim = decoded;
    } catch (error) {
      return mismatch(error instanceof Error ? error.message : String(error));
    }

    // Delegate authorizes a different account to send this transaction, which
    // would route around the payTo authorization check below; Signers is the
    // multisig equivalent.
    if ((claim as { Delegate?: unknown }).Delegate !== undefined) {
      return mismatch("Delegate not allowed");
    }
    if ((claim as { Signers?: unknown }).Signers !== undefined) {
      return mismatch("multisig not supported");
    }

    const signingPubKey = (claim as { SigningPubKey?: unknown }).SigningPubKey;
    if (
      typeof signingPubKey !== "string" ||
      !CANONICAL_SIGNING_PUB_KEY_PATTERN.test(signingPubKey)
    ) {
      return mismatch("SigningPubKey missing or non-canonical");
    }
    // The pattern checks shape, not curve membership, and verifySignature
    // throws rather than returning false for a key that is off the curve.
    let transactionSignatureValid: boolean;
    try {
      transactionSignatureValid = verifySignature(settlementBlob);
    } catch {
      transactionSignatureValid = false;
    }
    if (!transactionSignatureValid) {
      return mismatch("transaction signature invalid");
    }
    if (claim.Account !== requirements.payTo) {
      return mismatch("Account is not payTo");
    }
    if (
      typeof claim.Channel !== "string" ||
      claim.Channel.toUpperCase() !== uptoPayload.channelId.toUpperCase()
    ) {
      return mismatch("Channel mismatch");
    }
    const networkId = parseXrplNetworkId(requirements.network);
    if (networkId <= 1024 && claim.NetworkID !== undefined) {
      return mismatch("NetworkID set for a standard network");
    }
    if (networkId > 1024 && claim.NetworkID !== networkId) {
      return mismatch("NetworkID mismatch");
    }
    // The dedup entry is sized from this window, and a claim that can never
    // land would otherwise hold the entry for its whole TTL.
    if (typeof claim.LastLedgerSequence !== "number") {
      return mismatch("LastLedgerSequence missing");
    }
    if (claim.LastLedgerSequence <= currentLedgerIndex) {
      return mismatch("LastLedgerSequence already passed");
    }
    if (
      claim.LastLedgerSequence >
      getMaxSettlementLastLedgerSequence(currentLedgerIndex, requirements)
    ) {
      return mismatch("LastLedgerSequence beyond the settlement window");
    }
    const flags = typeof claim.Flags === "number" ? claim.Flags : 0;
    if ((flags & PaymentChannelClaimFlags.tfClose) === 0) {
      return mismatch("tfClose not set");
    }
    if ((flags & PaymentChannelClaimFlags.tfRenew) !== 0) {
      return mismatch("tfRenew set");
    }

    if (bareClose) {
      // Neither a zero charge nor one the channel already delivered can be
      // expressed as a claim; each is a bare destination close (see
      // buildSettlementTransaction on the server).
      if (
        claim.Balance !== undefined ||
        claim.Amount !== undefined ||
        claim.Signature !== undefined ||
        claim.PublicKey !== undefined
      ) {
        return mismatch("zero or pre-delivered settlement must be a bare close");
      }
      return { signingPubKey, lastLedgerSequence: claim.LastLedgerSequence };
    }

    if (parseDrops(claim.Balance) !== settleAmount) {
      return mismatch("Balance mismatch");
    }
    if (parseDrops(claim.Amount) !== BigInt(uptoPayload.maxAmount)) {
      return mismatch("Amount is not the authorized maximum");
    }
    if ((claim.Signature ?? "").toUpperCase() !== uptoPayload.signature.toUpperCase()) {
      return mismatch("Signature is not the payer claim signature");
    }
    if ((claim.PublicKey ?? "").toUpperCase() !== uptoPayload.publicKey.toUpperCase()) {
      return mismatch("PublicKey mismatch");
    }
    return { signingPubKey, lastLedgerSequence: claim.LastLedgerSequence };
  }

  /**
   * Verifies that the settlement blob's signing key is authorized for payTo.
   *
   * @param signingPubKey - The blob's embedded signing public key
   * @param requirements - Payment requirements
   * @returns Invalid reason, if validation fails
   */
  private async verifySettlementSigner(
    signingPubKey: string,
    requirements: PaymentRequirements,
  ): Promise<string | undefined> {
    const signerAddress = deriveAddress(signingPubKey);
    const authorization = await getXrplAccountAuthorization(
      requirements.payTo,
      requirements.network,
      this.options,
    );
    // rippled (fixMasterKeyAsRegularKey) authorizes the configured regular key
    // first, then the master key pair unless it is disabled.
    if (authorization.regularKey === signerAddress) {
      return undefined;
    }
    if (signerAddress === requirements.payTo && !authorization.isMasterKeyDisabled) {
      return undefined;
    }
    return "invalid_upto_xrpl_settlement_signer_not_authorized";
  }
}

/**
 * Creates an invalid verification response.
 *
 * @param reason - Invalid reason
 * @param payer - Payer address, if known
 * @param message - Human-readable invalidation detail, if available
 * @returns Invalid verify response
 */
function invalidVerify(reason: string, payer: string, message?: string): VerifyResponse {
  return {
    isValid: false,
    invalidReason: reason,
    invalidMessage: message,
    payer,
  };
}

/**
 * Creates a failed settlement response.
 *
 * @param reason - Machine-readable error reason
 * @param network - Network identifier
 * @param payer - Payer address, if known
 * @param transaction - Transaction hash, when one was submitted
 * @param message - Human-readable failure detail, if available
 * @returns Failed settlement response
 */
function failedSettle(
  reason: string,
  network: Network,
  payer: string,
  transaction = "",
  message?: string,
): SettleResponse {
  return {
    success: false,
    transaction,
    network,
    payer,
    errorReason: reason,
    errorMessage: message,
  };
}

/**
 * Verifies the requirements are well-formed, independently of the payload.
 *
 * @param requirements - Payment requirements
 * @returns The required amount in drops, or an invalid reason
 */
function verifyRequirements(requirements: PaymentRequirements): bigint | string {
  if (requirements.asset !== "XRP") {
    return "invalid_upto_xrpl_asset";
  }
  if (!Number.isInteger(requirements.maxTimeoutSeconds) || requirements.maxTimeoutSeconds <= 0) {
    return "invalid_upto_xrpl_max_timeout_seconds";
  }
  // Canonical drops only: settle re-verifies with `amount` replaced by the
  // payload's `maxAmount` and compares the two as strings.
  const requiredAmount = parseDrops(requirements.amount);
  if (requiredAmount === undefined || requiredAmount.toString() !== requirements.amount) {
    return "invalid_upto_xrpl_required_amount";
  }
  const minSettleDelay = optional(requirements.extra?.minSettleDelay);
  if (minSettleDelay !== undefined && !isNonNegativeInteger(minSettleDelay)) {
    return "invalid_upto_xrpl_min_settle_delay_malformed";
  }
  const validAfter = optional(requirements.extra?.validAfter);
  if (validAfter !== undefined && !isNonNegativeInteger(validAfter)) {
    return "invalid_upto_xrpl_valid_after_malformed";
  }
  return requiredAmount;
}

/**
 * Normalizes an absent optional wire field to `undefined`.
 *
 * @param value - Optional field value
 * @returns The value, or undefined when it is null
 */
function optional(value: unknown): unknown {
  return value ?? undefined;
}

/**
 * Reads the channel's final cumulative Balance from claim metadata.
 *
 * @param meta - Validated transaction metadata, if the submission returned it
 * @param channelId - Index of the PayChannel ledger object
 * @returns The final Balance in drops, or undefined when unavailable
 */
function getFinalChannelBalance(
  meta: TransactionMetadata | undefined,
  channelId: string,
): bigint | undefined {
  // Metadata is optional evidence: junk from a custom submission seam reads
  // as no evidence, not as a failed payment.
  try {
    for (const affectedNode of meta?.AffectedNodes ?? []) {
      const node =
        "DeletedNode" in affectedNode
          ? affectedNode.DeletedNode
          : "ModifiedNode" in affectedNode
            ? affectedNode.ModifiedNode
            : undefined;
      if (
        node?.LedgerEntryType === "PayChannel" &&
        node.LedgerIndex.toUpperCase() === channelId.toUpperCase()
      ) {
        return parseDrops((node.FinalFields as { Balance?: unknown } | undefined)?.Balance);
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
}
