import type {
  AssetAmount,
  Money,
  MoneyParser,
  Network,
  PaymentPayload,
  PaymentRequirements,
  Price,
  SchemeNetworkServer,
  SupportedKind,
} from "@x402/core/types";
import { parseMoneyString } from "@x402/core/utils";
import { PaymentChannelClaimFlags, type PaymentChannelClaim } from "xrpl";
import {
  createXrplClient,
  getUptoXrplPayload,
  isIntegerString,
  isNonNegativeInteger,
  isXrplNetwork,
  parseDrops,
  parseXrplNetworkId,
  requireClassicAddress,
} from "../../utils";
import type { ClientXrplSigner, UptoXrplPayload, UptoXrplServerOptions } from "../../types";

/**
 * XRPL server implementation for the upto payment scheme.
 *
 * Besides building requirements, the server signs the settlement: closing a
 * channel atomically requires the transaction to originate from the channel
 * `Destination`, so the `PaymentChannelClaim` is built and signed here, by
 * the party that knows the actual charge, and the facilitator only verifies
 * and relays it.
 */
export class UptoXrplScheme implements SchemeNetworkServer {
  readonly scheme = "upto";
  private moneyParsers: MoneyParser[] = [];

  /**
   * Creates a new XRPL upto server scheme.
   *
   * @param signer - Signer authorized for the payTo account; it signs each
   *   settlement claim. May be the account's regular key.
   * @param options - Optional server configuration
   */
  constructor(
    private readonly signer: ClientXrplSigner,
    private readonly options: UptoXrplServerOptions = {},
  ) {}

  /**
   * Register a custom money parser in the parser chain.
   *
   * @param parser - Custom money parser
   * @returns This server scheme
   */
  registerMoneyParser(parser: MoneyParser): UptoXrplScheme {
    this.moneyParsers.push(parser);
    return this;
  }

  /**
   * Parses a price into an XRPL asset amount.
   *
   * @param price - Price to parse
   * @param network - Network identifier
   * @returns Parsed asset amount
   */
  async parsePrice(price: Price, network: Network): Promise<AssetAmount> {
    if (typeof price === "object" && price !== null && "amount" in price) {
      if (!price.asset) {
        throw new Error(`Asset must be specified for AssetAmount on network ${network}`);
      }
      const result = {
        amount: price.amount,
        asset: price.asset,
        extra: price.extra || {},
      };
      this.validateAssetAmount(result);
      return result;
    }

    const amount = this.parseMoneyToDecimal(price);
    for (const parser of this.moneyParsers) {
      const result = await parser(amount, network);
      if (result !== null) {
        this.validateAssetAmount(result);
        return result;
      }
    }

    throw new Error("XRPL upto payments require explicit AssetAmount pricing");
  }

  /**
   * Enhances XRPL upto payment requirements with fee metadata.
   *
   * @param paymentRequirements - Base payment requirements
   * @param supportedKind - Facilitator-supported kind
   * @param extensionKeys - Supported facilitator extension keys
   * @returns Enhanced payment requirements
   */
  enhancePaymentRequirements(
    paymentRequirements: PaymentRequirements,
    supportedKind: SupportedKind,
    extensionKeys: string[],
  ): Promise<PaymentRequirements> {
    void supportedKind;
    void extensionKeys;

    const minSettleDelay = paymentRequirements.extra?.minSettleDelay;
    if (minSettleDelay != null && !isNonNegativeInteger(minSettleDelay)) {
      throw new Error("XRPL upto payments require extra.minSettleDelay in whole seconds");
    }
    const validAfter = paymentRequirements.extra?.validAfter;
    if (validAfter != null && !isNonNegativeInteger(validAfter)) {
      throw new Error("XRPL upto payments require extra.validAfter in Unix seconds");
    }
    // Settle-time only; a challenge must never carry a signed claim.
    if (paymentRequirements.extra?.settlementTransaction !== undefined) {
      throw new Error("extra.settlementTransaction must be absent from PAYMENT-REQUIRED");
    }

    return Promise.resolve({
      ...paymentRequirements,
      extra: {
        ...paymentRequirements.extra,
        areFeesSponsored: false,
      },
    });
  }

  /**
   * Builds the settle-time requirements for a verified upto payment.
   *
   * Called after the metered work has run, with `requirements.amount` set to
   * the actual charge. Signs the `PaymentChannelClaim` that closes the
   * channel and returns the requirements with the blob in
   * `extra.settlementTransaction`, ready for the facilitator's `/settle`.
   *
   * @param paymentPayload - Verified x402 payment payload
   * @param requirements - Payment requirements with amount set to the actual charge
   * @returns Settle-time payment requirements
   */
  async buildSettlementRequirements(
    paymentPayload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<PaymentRequirements> {
    if (requirements.scheme !== "upto") {
      throw new Error(`Unsupported scheme: ${requirements.scheme}`);
    }
    if (!isXrplNetwork(requirements.network)) {
      throw new Error(`Unsupported XRPL network: ${requirements.network}`);
    }
    if (requirements.asset !== "XRP") {
      throw new Error("XRPL upto payments support XRP only");
    }
    requireClassicAddress(requirements.payTo, "payTo");

    const uptoPayload = getUptoXrplPayload(paymentPayload);
    if (!uptoPayload) {
      throw new Error("XRPL upto payload is malformed");
    }
    const settleAmount = parseDrops(requirements.amount);
    if (settleAmount === undefined || settleAmount.toString() !== requirements.amount) {
      throw new Error("XRPL upto settlement requires amount as canonical integer drops");
    }
    const maxAmount = parseDrops(uptoPayload.maxAmount);
    if (maxAmount === undefined || settleAmount > maxAmount) {
      throw new Error("XRPL upto settlement amount exceeds the authorized maximum");
    }

    const claim = this.buildSettlementTransaction(uptoPayload, requirements, settleAmount);
    const prepared = await this.prepareSettlementTransaction(claim, requirements);
    this.validatePreparedSettlementTransaction(prepared, requirements.network);
    const signed = await this.signer.sign(prepared);

    return {
      ...requirements,
      extra: {
        ...requirements.extra,
        settlementTransaction: signed.signedTxBlob,
      },
    };
  }

  /**
   * Builds the unsigned settlement claim per the scheme's binding rules.
   *
   * `Amount` carries the authorized maximum the payer signed over, never the
   * settlement amount, and `Balance` the actual charge. A zero settlement is
   * a bare destination close: the ledger requires a claim's `Balance` to
   * exceed the delivered total, so zero cannot be expressed as a claim.
   *
   * @param uptoPayload - XRPL upto payload
   * @param requirements - Payment requirements with amount set to the actual charge
   * @param settleAmount - Actual settlement amount in drops
   * @returns Unsigned PaymentChannelClaim
   */
  private buildSettlementTransaction(
    uptoPayload: UptoXrplPayload,
    requirements: PaymentRequirements,
    settleAmount: bigint,
  ): PaymentChannelClaim {
    const networkId = parseXrplNetworkId(requirements.network);
    return {
      TransactionType: "PaymentChannelClaim",
      Account: requirements.payTo,
      Channel: uptoPayload.channelId,
      Flags: PaymentChannelClaimFlags.tfClose,
      ...(settleAmount > 0n
        ? {
            Balance: requirements.amount,
            Amount: uptoPayload.maxAmount,
            Signature: uptoPayload.signature,
            PublicKey: uptoPayload.publicKey,
          }
        : {}),
      ...(networkId > 1024 ? { NetworkID: networkId } : {}),
    };
  }

  /**
   * Prepares the settlement claim with ledger-derived fields before signing.
   *
   * @param transaction - Locally built settlement claim
   * @param requirements - Payment requirements to satisfy
   * @returns Prepared settlement claim
   */
  private async prepareSettlementTransaction(
    transaction: PaymentChannelClaim,
    requirements: PaymentRequirements,
  ): Promise<PaymentChannelClaim> {
    if (this.options.prepareSettlementTransaction) {
      return this.options.prepareSettlementTransaction(transaction, requirements);
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
   * Ensures the claim can be submitted after signing.
   *
   * @param transaction - Prepared settlement claim
   * @param network - XRPL network id
   */
  private validatePreparedSettlementTransaction(
    transaction: PaymentChannelClaim,
    network: Network,
  ): void {
    if (transaction.TransactionType !== "PaymentChannelClaim") {
      throw new Error("prepareSettlementTransaction must return a PaymentChannelClaim");
    }
    if (typeof transaction.Fee !== "string" || !isIntegerString(transaction.Fee)) {
      throw new Error("prepareSettlementTransaction must set Fee in drops");
    }
    // The facilitator bounds the claim's landable window from this field and
    // rejects a claim without one.
    if (typeof transaction.LastLedgerSequence !== "number") {
      throw new Error("prepareSettlementTransaction must set LastLedgerSequence");
    }
    const networkId = parseXrplNetworkId(network);
    if (networkId <= 1024 && transaction.NetworkID !== undefined) {
      throw new Error(
        "prepareSettlementTransaction must not set NetworkID for standard XRPL networks",
      );
    }
    if (networkId > 1024 && transaction.NetworkID !== networkId) {
      throw new Error("prepareSettlementTransaction must set NetworkID for custom XRPL networks");
    }
  }

  /**
   * Parses a Money value for custom parser dispatch.
   *
   * @param money - Money value to parse
   * @returns Decimal number
   */
  private parseMoneyToDecimal(money: Money): number {
    if (typeof money === "number") {
      if (!Number.isFinite(money) || money < 0) {
        throw new Error(`Invalid money format: ${money}`);
      }
      return money;
    }

    return parseMoneyString(money);
  }

  /**
   * Validates parsed XRPL upto asset amounts.
   *
   * @param assetAmount - Parsed asset amount
   */
  private validateAssetAmount(assetAmount: AssetAmount): void {
    if (assetAmount.asset !== "XRP") {
      throw new Error("XRPL upto payments support XRP only");
    }
    if (!isIntegerString(assetAmount.amount)) {
      throw new Error("XRPL native payments require amount as an integer drops string");
    }
  }
}
