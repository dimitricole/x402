import type {
  Client,
  Payment,
  PaymentChannelClaim,
  PaymentChannelCreate,
  SubmittableTransaction,
  TransactionMetadata,
} from "xrpl";
import type { Network, PaymentRequirements } from "@x402/core/types";

/**
 * XRPL CAIP-2 network identifier.
 */
export type XrplNetwork = `xrpl:${number}`;

/**
 * Asset transfer methods supported by the XRPL exact scheme.
 *
 * - `sequence`: the signed transaction consumes the payer account's current
 *   `Sequence`, so each account has at most one pending payment.
 * - `ticketSequence`: the signed transaction consumes a pre-created XRPL
 *   Ticket (`Sequence = 0` plus `TicketSequence`), allowing multiple
 *   concurrent pending payments per account.
 */
export type XrplAssetTransferMethod = "sequence" | "ticketSequence";

/**
 * XRPL exact scheme payload.
 */
export type ExactXrplPayload = {
  /**
   * Hex-encoded signed XRPL transaction blob.
   */
  signedTxBlob: string;
};

/**
 * Extra payment requirements for XRPL exact payments.
 */
export type XrplPaymentRequirementsExtra = {
  /**
   * Always false: the payer pays the XRPL transaction fee embedded in the
   * signed transaction, so facilitator fee sponsorship is not supported.
   */
  areFeesSponsored: boolean;
  /**
   * Selects how the signed transaction is sequenced. Defaults to "sequence".
   */
  assetTransferMethod?: XrplAssetTransferMethod;
  /**
   * Unique invoice id committed into the signed transaction.
   */
  invoiceId?: string;
  /**
   * Optional destination tag required by the receiver.
   */
  destinationTag?: number;
  /**
   * Required IOU issuer address for issued-currency payments.
   */
  issuer?: string;
};

/**
 * XRPL upto scheme payload.
 */
export type UptoXrplPayload = {
  /**
   * Index of the `PayChannel` ledger object.
   */
  channelId: string;
  /**
   * Drops authorized by `signature`. Must equal the amount the payer signed.
   */
  maxAmount: string;
  /**
   * Payer's off-ledger claim signature over `(channelId, maxAmount)`.
   */
  signature: string;
  /**
   * Channel `PublicKey`. The ledger verifies the claim against it.
   */
  publicKey: string;
  /**
   * Channel `Account`, i.e. the payer's classic address.
   */
  payer: string;
  /**
   * Settle-time only: hex blob of the `PaymentChannelClaim` signed by the
   * `payTo` account, which the facilitator verifies and submits. Added by the
   * resource server's settlement-payload enrichment; verification rejects a
   * client-supplied value.
   */
  settlementTransaction?: string;
};

/**
 * Extra payment requirements for XRPL upto payments.
 */
export type UptoXrplPaymentRequirementsExtra = {
  /**
   * Always false: the payer funds the channel and pays its creation fee.
   */
  areFeesSponsored: boolean;
  /**
   * Minimum `SettleDelay` the channel must carry, in seconds. Prevents a payer
   * from stranding settlement by racing a source-initiated close.
   */
  minSettleDelay?: number;
  /**
   * Earliest activation time in Unix seconds, enforced at verification
   * against the validated ledger's close time.
   */
  validAfter?: number;
};

/**
 * Fields of a `PayChannel` ledger object relevant to the upto scheme.
 */
export type PayChannelEntry = {
  LedgerEntryType: "PayChannel";
  Account: string;
  Destination: string;
  Amount: string;
  /** Total delivered so far. "0" on an unspent channel. */
  Balance: string;
  PublicKey: string;
  SettleDelay: number;
  CancelAfter?: number;
  Expiration?: number;
};

/**
 * Client signer abstraction for XRPL transactions.
 */
export type ClientXrplSigner = {
  /**
   * XRPL classic address that signs and pays the transaction fee.
   */
  classicAddress: string;
  /**
   * Sign an XRPL transaction without submitting it.
   */
  sign(
    transaction: SubmittableTransaction,
  ): Promise<{ signedTxBlob: string; hash?: string }> | { signedTxBlob: string; hash?: string };
};

/**
 * Client signer for XRPL upto payments.
 *
 * The channel is created with `publicKey` and the off-ledger claim must
 * verify against it, so both key operations must come from one key pair.
 */
export type UptoClientXrplSigner = ClientXrplSigner & {
  /**
   * Hex public key placed on the channel as `PublicKey`.
   */
  publicKey: string;
  /**
   * Signs the off-ledger claim over `(channelId, amount)`, amount in drops.
   */
  signClaim(channelId: string, amountDrops: string): Promise<string> | string;
};

/**
 * Options for XRPL upto client payment creation.
 */
export type UptoXrplClientOptions = {
  /**
   * Optional fee to place on the channel-create transaction, in drops.
   */
  feeDrops?: string;
  /**
   * Optional function used to read the validated ledger's close time, in
   * Ripple-epoch seconds. The channel's CancelAfter derives from it.
   */
  getLedgerCloseTime?: (network: Network) => Promise<number>;
  /**
   * Optional function to prepare/autofill the channel-create transaction
   * before signing.
   */
  prepareChannelCreateTransaction?: (
    transaction: PaymentChannelCreate,
    requirements: PaymentRequirements,
  ) => Promise<PaymentChannelCreate>;
  /**
   * Optional custom submission function for tests or custom infrastructure.
   */
  submitSignedTransaction?: (
    signedTxBlob: string,
    network: Network,
  ) => Promise<XrplSettlementResult>;
  /**
   * Optional WebSocket endpoint map by x402 network id.
   */
  wsUrlByNetwork?: Partial<Record<XrplNetwork, string>>;
  /**
   * Optional XRPL client factory.
   */
  clientFactory?: XrplClientFactory;
};

/**
 * Options for XRPL upto server settlement building.
 */
export type UptoXrplServerOptions = {
  /**
   * Optional function to prepare/autofill the settlement claim before
   * signing. Defaults to xrpl.js autofill, which sets `Sequence`, `Fee` and
   * `LastLedgerSequence`.
   */
  prepareSettlementTransaction?: (
    transaction: PaymentChannelClaim,
    requirements: PaymentRequirements,
  ) => Promise<PaymentChannelClaim>;
  /**
   * Optional function used to read a `PayChannel` ledger object, from which
   * settlement decides between a claim and a bare close. Defaults to a
   * validated ledger_entry lookup. Returns undefined when the entry does not
   * exist.
   */
  getPayChannel?: (channelId: string, network: Network) => Promise<PayChannelEntry | undefined>;
  /**
   * Optional WebSocket endpoint map by x402 network id.
   */
  wsUrlByNetwork?: Partial<Record<XrplNetwork, string>>;
  /**
   * Optional XRPL client factory.
   */
  clientFactory?: XrplClientFactory;
};

/**
 * Options for XRPL exact client payment creation.
 */
export type XrplClientOptions = {
  /**
   * Optional fee to place on locally-built transactions, in drops.
   */
  feeDrops?: string;
  /**
   * Optional function used to fetch current validated ledger index.
   */
  getCurrentLedgerIndex?: (network: Network) => Promise<number>;
  /**
   * Optional function returning an available ticket sequence for
   * ticketSequence payments. Defaults to reading the account's validated
   * ticket objects from the ledger.
   */
  getAvailableTicketSequence?: (account: string, network: Network) => Promise<number | undefined>;
  /**
   * Number of tickets to create when a ticketSequence payment finds none.
   * Defaults to 1. Set to 0 to disable automatic ticket creation.
   */
  ticketCreateCount?: number;
  /**
   * Optional function to prepare/autofill the transaction before signing.
   */
  preparePaymentTransaction?: (
    transaction: Payment,
    requirements: PaymentRequirements,
  ) => Promise<Payment>;
  /**
   * Optional WebSocket endpoint map by x402 network id.
   */
  wsUrlByNetwork?: Partial<Record<XrplNetwork, string>>;
  /**
   * Optional XRPL client factory.
   */
  clientFactory?: XrplClientFactory;
};

/**
 * Result of submitting a signed XRPL transaction.
 */
export type XrplSettlementResult = {
  /**
   * XRPL transaction hash.
   */
  hash: string;
  /**
   * Whether the returned result is validated.
   */
  validated: boolean;
  /**
   * XRPL transaction result code.
   */
  resultCode: string;
  /**
   * Validated transaction metadata, when the submission path provides it.
   * The upto scheme uses it to confirm the delivered amount.
   */
  meta?: TransactionMetadata;
};

/**
 * Result of simulating a signed XRPL transaction.
 */
export type XrplSimulationResult = {
  /**
   * XRPL engine result code returned by simulate.
   */
  engineResult: string;
  /**
   * Human-readable engine result message.
   */
  engineResultMessage?: string;
};

/**
 * Signing authorization state for an XRPL account.
 */
export type XrplAccountAuthorization = {
  /**
   * Classic address of the account's configured regular key, if one is set.
   */
  regularKey?: string;
  /**
   * Whether the account's master key pair is disabled (lsfDisableMaster).
   */
  isMasterKeyDisabled: boolean;
};

/**
 * Factory for creating XRPL SDK clients.
 */
export type XrplClientFactory = (wsUrl: string) => Client;

/**
 * Options for XRPL facilitator verification and settlement.
 */
export type XrplFacilitatorOptions = {
  /**
   * Maximum accepted fee in drops.
   */
  maxFeeDrops?: string;
  /**
   * Optional function used to fetch current validated ledger index.
   */
  getCurrentLedgerIndex?: (network: Network) => Promise<number>;
  /**
   * Optional function used to fetch the account's current on-network
   * sequence. Defaults to a validated account_info lookup.
   */
  getAccountSequence?: (account: string, network: Network) => Promise<number>;
  /**
   * Optional function used to fetch the account's signing authorization
   * (regular key and master-key status). Defaults to a validated
   * account_info lookup.
   */
  getAccountAuthorization?: (
    account: string,
    network: Network,
  ) => Promise<XrplAccountAuthorization>;
  /**
   * Optional function used to check ticket availability for an account.
   * Defaults to a validated account_objects lookup.
   */
  isTicketAvailable?: (
    account: string,
    ticketSequence: number,
    network: Network,
  ) => Promise<boolean>;
  /**
   * Optional function used to read a `PayChannel` ledger object. Defaults to
   * a validated ledger_entry lookup. Returns undefined when the entry does
   * not exist.
   */
  getPayChannel?: (channelId: string, network: Network) => Promise<PayChannelEntry | undefined>;
  /**
   * Optional function used to read the validated ledger's close time, in
   * Ripple-epoch seconds. Defaults to a validated ledger lookup.
   */
  getLedgerCloseTime?: (network: Network) => Promise<number>;
  /**
   * Optional custom submission function for tests or custom infrastructure.
   */
  submitSignedTransaction?: (
    signedTxBlob: string,
    network: Network,
  ) => Promise<XrplSettlementResult>;
  /**
   * Optional custom simulation function for tests or custom infrastructure.
   */
  simulateSignedTransaction?: (
    signedTxBlob: string,
    network: Network,
  ) => Promise<XrplSimulationResult>;
  /**
   * Optional WebSocket endpoint map by x402 network id.
   */
  wsUrlByNetwork?: Partial<Record<XrplNetwork, string>>;
  /**
   * Optional XRPL client factory.
   */
  clientFactory?: XrplClientFactory;
};
