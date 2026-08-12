import { LANDING_MARGIN_SECONDS } from "../../constants";
import {
  createXrplClient,
  getLedgerCloseTime,
  isIntegerString,
  isNonNegativeInteger,
  isXrplNetwork,
  parseDrops,
  parseXrplNetworkId,
  submitSignedTransaction,
} from "../../utils";
import type { UptoClientXrplSigner, UptoXrplClientOptions } from "../../types";
import type {
  PaymentPayloadResult,
  PaymentRequirements,
  SchemeNetworkClient,
} from "@x402/core/types";
import { hashes, type PaymentChannelCreate } from "xrpl";

/**
 * XRPL client implementation for the upto payment scheme.
 *
 * Escrows the authorized maximum in a Payment Channel and signs one
 * off-ledger claim over `(channelId, maxAmount)`; the destination later
 * claims the actual amount and closes the channel, refunding the remainder.
 */
export class UptoXrplScheme implements SchemeNetworkClient {
  readonly scheme = "upto";

  /**
   * Creates a new XRPL upto client scheme.
   *
   * @param signer - XRPL signer that funds the channel and signs the claim
   * @param options - Optional client configuration
   */
  constructor(
    private readonly signer: UptoClientXrplSigner,
    private readonly options: UptoXrplClientOptions = {},
  ) {}

  /**
   * Creates an XRPL upto payment payload.
   *
   * Submits a `PaymentChannelCreate` escrowing the authorized maximum, waits
   * for it to validate, and signs the off-ledger claim the payload carries.
   *
   * @param x402Version - x402 protocol version
   * @param paymentRequirements - Payment requirements from the resource server
   * @returns Payment payload authorizing up to the required amount
   */
  async createPaymentPayload(
    x402Version: number,
    paymentRequirements: PaymentRequirements,
  ): Promise<PaymentPayloadResult> {
    this.validatePaymentRequirements(paymentRequirements);

    const unsignedCreate = await this.buildChannelCreateTransaction(paymentRequirements);
    const prepared = await this.prepareChannelCreateTransaction(
      unsignedCreate,
      paymentRequirements,
    );
    this.validatePreparedChannelCreateTransaction(prepared, paymentRequirements);
    const signed = await this.signer.sign(prepared);

    const result = await submitSignedTransaction(
      signed.signedTxBlob,
      paymentRequirements.network,
      this.options,
    );
    if (!result.validated || result.resultCode !== "tesSUCCESS") {
      throw new Error(`PaymentChannelCreate failed: ${result.resultCode}`);
    }

    const channelId = hashes.hashPaymentChannel(
      this.signer.classicAddress,
      paymentRequirements.payTo,
      prepared.Sequence as number,
    );
    const signature = await this.signer.signClaim(channelId, paymentRequirements.amount);

    return {
      x402Version,
      payload: {
        channelId,
        maxAmount: paymentRequirements.amount,
        signature,
        publicKey: this.signer.publicKey,
        payer: this.signer.classicAddress,
      },
    };
  }

  /**
   * Builds the XRPL PaymentChannelCreate transaction the payer will sign.
   *
   * @param requirements - Payment requirements to encode
   * @returns Unsigned XRPL channel-create transaction
   */
  private async buildChannelCreateTransaction(
    requirements: PaymentRequirements,
  ): Promise<PaymentChannelCreate> {
    const networkId = parseXrplNetworkId(requirements.network);
    const ledgerCloseTime = await getLedgerCloseTime(requirements.network, this.options);

    const minSettleDelay = requirements.extra?.minSettleDelay;
    // Verification requires the delay to cover the metered work plus the
    // landing, so a mid-work source close cannot expire the channel under
    // the claim.
    const settleDelay = Math.max(
      requirements.maxTimeoutSeconds + LANDING_MARGIN_SECONDS,
      typeof minSettleDelay === "number" ? minSettleDelay : 0,
    );
    // Verification demands maxTimeoutSeconds plus a landing margin remaining
    // on the channel, and the ledger clock advances before it runs: budget
    // one more margin for this transaction to land and one for the payment
    // to be presented.
    const cancelAfter =
      ledgerCloseTime + requirements.maxTimeoutSeconds + 3 * LANDING_MARGIN_SECONDS;

    return {
      TransactionType: "PaymentChannelCreate",
      Account: this.signer.classicAddress,
      Destination: requirements.payTo,
      Amount: requirements.amount,
      SettleDelay: settleDelay,
      PublicKey: this.signer.publicKey,
      CancelAfter: cancelAfter,
      ...(this.options.feeDrops !== undefined ? { Fee: this.options.feeDrops } : {}),
      ...(networkId > 1024 ? { NetworkID: networkId } : {}),
    };
  }

  /**
   * Prepares the channel-create transaction with ledger-derived fields.
   *
   * @param transaction - Locally built channel-create transaction
   * @param requirements - Payment requirements to satisfy
   * @returns Prepared channel-create transaction
   */
  private async prepareChannelCreateTransaction(
    transaction: PaymentChannelCreate,
    requirements: PaymentRequirements,
  ): Promise<PaymentChannelCreate> {
    if (this.options.prepareChannelCreateTransaction) {
      return this.options.prepareChannelCreateTransaction(transaction, requirements);
    }

    const client = createXrplClient(requirements.network, this.options);
    try {
      await client.connect();
      return await client.autofill(transaction);
    } finally {
      await client.disconnect();
    }
  }

  /**
   * Ensures the transaction can be submitted and its channel id derived.
   *
   * @param transaction - Prepared channel-create transaction
   * @param requirements - Payment requirements to satisfy
   */
  private validatePreparedChannelCreateTransaction(
    transaction: PaymentChannelCreate,
    requirements: PaymentRequirements,
  ): void {
    if (transaction.TransactionType !== "PaymentChannelCreate") {
      throw new Error("prepareChannelCreateTransaction must return a PaymentChannelCreate");
    }
    // The channel id is SHA512Half(0x0078, source, destination, sequence), so
    // a ticket-sequenced create would derive a different channel than the one
    // the ledger creates.
    if (typeof transaction.Sequence !== "number" || transaction.Sequence === 0) {
      throw new Error("prepareChannelCreateTransaction must set the account Sequence");
    }
    if (typeof transaction.Fee !== "string" || !isIntegerString(transaction.Fee)) {
      throw new Error("prepareChannelCreateTransaction must set Fee in drops");
    }
    if (typeof transaction.LastLedgerSequence !== "number") {
      throw new Error("prepareChannelCreateTransaction must set LastLedgerSequence");
    }
    const networkId = parseXrplNetworkId(requirements.network);
    if (networkId <= 1024 && transaction.NetworkID !== undefined) {
      throw new Error(
        "prepareChannelCreateTransaction must not set NetworkID for standard XRPL networks",
      );
    }
    if (networkId > 1024 && transaction.NetworkID !== networkId) {
      throw new Error(
        "prepareChannelCreateTransaction must set NetworkID for custom XRPL networks",
      );
    }
  }

  /**
   * Validates requirements before escrowing the authorized maximum.
   *
   * @param requirements - Payment requirements to validate
   */
  private validatePaymentRequirements(requirements: PaymentRequirements): void {
    if (requirements.scheme !== "upto") {
      throw new Error(`Unsupported scheme: ${requirements.scheme}`);
    }
    if (!isXrplNetwork(requirements.network)) {
      throw new Error(`Unsupported XRPL network: ${requirements.network}`);
    }
    if (requirements.asset !== "XRP") {
      throw new Error("XRPL upto payments support XRP only");
    }
    // Canonical drops: the payload's maxAmount must equal the requirement
    // amount string exactly, and the claim signs over it.
    const amount = parseDrops(requirements.amount);
    if (amount === undefined || amount.toString() !== requirements.amount) {
      throw new Error("XRPL upto payments require amount as canonical integer drops");
    }
    if (!Number.isInteger(requirements.maxTimeoutSeconds) || requirements.maxTimeoutSeconds <= 0) {
      throw new Error("XRPL upto payments require a positive integer maxTimeoutSeconds");
    }
    if (requirements.extra?.areFeesSponsored !== false) {
      throw new Error(
        "XRPL upto payments require extra.areFeesSponsored to be false; the payer pays the channel fees",
      );
    }
    const minSettleDelay = requirements.extra?.minSettleDelay;
    if (minSettleDelay != null && !isNonNegativeInteger(minSettleDelay)) {
      throw new Error("XRPL upto payments require extra.minSettleDelay in whole seconds");
    }
  }
}
