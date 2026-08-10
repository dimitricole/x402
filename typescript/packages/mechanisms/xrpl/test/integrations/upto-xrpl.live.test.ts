/**
 * Live XRPL upto settlement check. Skipped unless XRPL_LIVE_UPTO is set, so it
 * is inert in CI and runs only when explicitly requested.
 *
 * Both wallets are funded from the network faucet at runtime: the upto
 * settlement claim must be signed by the channel `Destination`, so the
 * resource server needs the payTo key, not just its address, and a faucet
 * wallet provides one without any preconfigured account.
 *
 * It drives the reference client, server and facilitator end to end against a
 * real network: the client escrows the authorized maximum in a real
 * `PayChannel`, the facilitator verifies it against the validated ledger, the
 * server signs a `PaymentChannelClaim` for an actual charge below that
 * maximum, and the assertions are on the ledger: payTo gains exactly the
 * settled drops, the close deletes the channel, and the payer recovers the
 * unspent remainder.
 *
 * Run (testnet):
 *   XRPL_LIVE_UPTO=1 pnpm test:integration
 */
import { Wallet } from "xrpl";
import { beforeAll, describe, expect, it } from "vitest";
import { x402Client } from "@x402/core/client";
import { x402Facilitator } from "@x402/core/facilitator";
import { type FacilitatorClient, x402ResourceServer } from "@x402/core/server";
import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
  SettleResponse,
  SupportedResponse,
  VerifyResponse,
} from "@x402/core/types";
import { DEFAULT_MAX_FEE_DROPS, XRPL_DEVNET, XRPL_TESTNET } from "../../src/constants";
import { createUptoXrplWalletSigner, createXrplWalletSigner } from "../../src/signer";
import { UptoXrplScheme as UptoXrplClient } from "../../src/upto/client";
import { UptoXrplScheme as UptoXrplFacilitator } from "../../src/upto/facilitator";
import { UptoXrplScheme as UptoXrplServer } from "../../src/upto/server";
import {
  createXrplClient,
  decodeSignedTransactionBlob,
  getPayChannel,
  getUptoXrplPayload,
  isXrplNetwork,
} from "../../src/utils";

const network = (process.env.XRPL_LIVE_NETWORK ?? XRPL_TESTNET) as Network;
// Faucet funding only exists on test networks, which also guarantees this
// test can never touch mainnet through a stray XRPL_LIVE_NETWORK.
const HAS_FAUCET = network === XRPL_TESTNET || network === XRPL_DEVNET;
const ENABLED = process.env.XRPL_LIVE_UPTO === "1";
const describeLive = ENABLED && HAS_FAUCET ? describe : describe.skip;

if (!ENABLED) {
  console.warn("[upto-xrpl.live] skipped: set XRPL_LIVE_UPTO=1 to run.");
} else if (!HAS_FAUCET) {
  console.warn(
    `[upto-xrpl.live] skipped: ${network} has no faucet; use ${XRPL_TESTNET} or ${XRPL_DEVNET}.`,
  );
}

const maxAmount = "1000000"; // drops escrowed as the authorized maximum
const settleAmount = "250000"; // the actual charge, deliberately below the maximum

/**
 * In-process facilitator client that adapts the reference facilitator for the
 * resource server used in this live test.
 */
class XrplFacilitatorClient implements FacilitatorClient {
  readonly scheme = "upto";
  readonly network = network;
  readonly x402Version = 2;
  /** Last payload forwarded to settle; carries the server-enriched claim. */
  lastSettlePayload?: PaymentPayload;

  /**
   * Creates the adapter around a configured x402 facilitator.
   *
   * @param facilitator - Facilitator with the XRPL upto scheme registered
   */
  constructor(private readonly facilitator: x402Facilitator) {}

  /**
   * Verifies a payment payload through the wrapped facilitator.
   *
   * @param paymentPayload - x402 payment payload
   * @param paymentRequirements - Payment requirements
   * @returns Verification response
   */
  verify(
    paymentPayload: PaymentPayload,
    paymentRequirements: PaymentRequirements,
  ): Promise<VerifyResponse> {
    return this.facilitator.verify(paymentPayload, paymentRequirements);
  }

  /**
   * Settles a payment payload through the wrapped facilitator.
   *
   * @param paymentPayload - x402 payment payload
   * @param paymentRequirements - Payment requirements
   * @returns Settlement response
   */
  settle(
    paymentPayload: PaymentPayload,
    paymentRequirements: PaymentRequirements,
  ): Promise<SettleResponse> {
    this.lastSettlePayload = paymentPayload;
    return this.facilitator.settle(paymentPayload, paymentRequirements);
  }

  /**
   * Reports the wrapped facilitator's supported kinds.
   *
   * @returns Supported response
   */
  getSupported(): Promise<SupportedResponse> {
    return Promise.resolve(this.facilitator.getSupported());
  }
}

/**
 * Reads the XRP balance of an account in drops from the validated ledger.
 *
 * @param account - XRPL classic address
 * @returns Balance in drops
 */
async function getXrpBalanceDrops(account: string): Promise<bigint> {
  if (!isXrplNetwork(network)) {
    throw new Error(`Unsupported XRPL network: ${network}`);
  }
  const client = createXrplClient(network, {});
  try {
    await client.connect();
    const response = await client.request({
      command: "account_info",
      account,
      ledger_index: "validated",
    });
    return BigInt(response.result.account_data.Balance);
  } finally {
    await client.disconnect();
  }
}

describeLive("XRPL upto live settlement", () => {
  let payerWallet: Wallet;
  let payToWallet: Wallet;
  let client: x402Client;
  let server: x402ResourceServer;
  let serverScheme: UptoXrplServer;
  let facilitatorClient: XrplFacilitatorClient;

  beforeAll(async () => {
    const xrpl = createXrplClient(network, {});
    await xrpl.connect();
    try {
      ({ wallet: payerWallet } = await xrpl.fundWallet());
      ({ wallet: payToWallet } = await xrpl.fundWallet());
    } finally {
      await xrpl.disconnect();
    }

    client = new x402Client().register(
      network,
      new UptoXrplClient(createUptoXrplWalletSigner(payerWallet)),
    );
    const facilitator = new x402Facilitator().register(network, new UptoXrplFacilitator());
    serverScheme = new UptoXrplServer(createXrplWalletSigner(payToWallet));
    facilitatorClient = new XrplFacilitatorClient(facilitator);
    server = new x402ResourceServer(facilitatorClient);
    server.register(network, serverScheme);
    await server.initialize();
  }, 120_000);

  /**
   * Opens a real channel for the authorized maximum and verifies the payment,
   * up to the point where the metered work would run.
   *
   * @returns The payload, the matched requirements and the channel id
   */
  async function createVerifiedPayment(): Promise<{
    paymentPayload: PaymentPayload;
    accepted: PaymentRequirements;
    channelId: string;
  }> {
    const accepts: PaymentRequirements[] = [
      {
        scheme: "upto",
        network,
        asset: "XRP",
        payTo: payToWallet.classicAddress,
        amount: maxAmount,
        maxTimeoutSeconds: 120,
        extra: { areFeesSponsored: false },
      } as PaymentRequirements,
    ];
    const resource = {
      url: "https://example.com/weather",
      description: "Weather data",
      mimeType: "application/json",
    };

    const paymentRequired = await server.createPaymentRequiredResponse(accepts, resource);
    const paymentPayload = await client.createPaymentPayload(paymentRequired);

    const accepted = server.findMatchingRequirements(paymentRequired.accepts, paymentPayload);
    expect(accepted).toBeDefined();

    const verify = await server.verifyPayment(paymentPayload, accepted!);
    expect(verify.isValid).toBe(true);
    expect(verify.payer).toBe(payerWallet.classicAddress);

    const uptoPayload = getUptoXrplPayload(paymentPayload);
    expect(uptoPayload).toBeDefined();
    return { paymentPayload, accepted: accepted!, channelId: uptoPayload!.channelId };
  }

  /**
   * Reads the fee the payTo account pays for the last settled claim, from the
   * server-enriched payload the facilitator received.
   *
   * @returns Claim fee in drops
   */
  function getClaimFeeDrops(): bigint {
    const uptoPayload = getUptoXrplPayload(facilitatorClient.lastSettlePayload!);
    const claim = decodeSignedTransactionBlob(uptoPayload!.settlementTransaction as string);
    return BigInt(claim.Fee!);
  }

  it("settles an actual charge below the authorized maximum and closes the channel", async () => {
    const payerBefore = await getXrpBalanceDrops(payerWallet.classicAddress);
    const payToBefore = await getXrpBalanceDrops(payToWallet.classicAddress);

    const { paymentPayload, accepted, channelId } = await createVerifiedPayment();

    const channel = await getPayChannel(channelId, network);
    expect(channel).toBeDefined();
    expect(channel!.Destination).toBe(payToWallet.classicAddress);
    expect(channel!.Amount).toBe(maxAmount);
    expect(channel!.Balance).toBe("0");

    // Two concurrent attempts against one channel: exactly one may reach the
    // ledger, the other must be refused by the duplicate-settlement guard.
    // Settlement enrichment signs the claim inside settlePayment.
    const results = await Promise.all([
      server.settlePayment(paymentPayload, accepted, undefined, undefined, {
        amount: settleAmount,
      }),
      server.settlePayment(paymentPayload, accepted, undefined, undefined, {
        amount: settleAmount,
      }),
    ]);
    const settled = results.filter(result => result.success);
    const refused = results.filter(result => !result.success);
    expect(settled).toHaveLength(1);
    expect(refused).toHaveLength(1);
    expect(refused[0].errorReason).toBe("duplicate_settlement");
    expect(settled[0].transaction).toMatch(/^[A-F0-9]{64}$/);
    expect(settled[0].amount).toBe(settleAmount);
    expect(settled[0].payer).toBe(payerWallet.classicAddress);

    // payTo is the claim's transaction Account and pays its fee, so the exact
    // delta nets it out.
    const payToAfter = await getXrpBalanceDrops(payToWallet.classicAddress);
    expect(payToAfter - payToBefore).toBe(BigInt(settleAmount) - getClaimFeeDrops());
    expect(await getPayChannel(channelId, network)).toBeUndefined();

    // The payer's only cost beyond the charge is the channel-create fee,
    // bounded here by the package's fee ceiling; a withheld refund of the
    // escrowed remainder blows far past it.
    const payerAfter = await getXrpBalanceDrops(payerWallet.classicAddress);
    const payerCost = payerBefore - payerAfter - BigInt(settleAmount);
    expect(payerCost).toBeGreaterThan(0n);
    expect(payerCost).toBeLessThan(BigInt(DEFAULT_MAX_FEE_DROPS));

    console.log(
      `[upto-xrpl.live] settled ${settleAmount} of ${maxAmount} drops on ${network}; ` +
        `channel=${channelId}; tx=${settled[0].transaction}; payTo ${payToBefore} -> ${payToAfter}`,
    );
  }, 240_000);

  it("settles zero as a bare close that refunds the deposit in full", async () => {
    const payerBefore = await getXrpBalanceDrops(payerWallet.classicAddress);
    const payToBefore = await getXrpBalanceDrops(payToWallet.classicAddress);

    const { paymentPayload, accepted, channelId } = await createVerifiedPayment();

    const settle = await server.settlePayment(paymentPayload, accepted, undefined, undefined, {
      amount: "0",
    });
    expect(settle.success).toBe(true);
    expect(settle.amount).toBe("0");
    expect(settle.transaction).toMatch(/^[A-F0-9]{64}$/);

    // A zero settlement is still an on-ledger close: payTo pays the claim fee
    // and receives nothing.
    const payToAfter = await getXrpBalanceDrops(payToWallet.classicAddress);
    expect(payToAfter - payToBefore).toBe(-getClaimFeeDrops());
    expect(await getPayChannel(channelId, network)).toBeUndefined();

    const payerAfter = await getXrpBalanceDrops(payerWallet.classicAddress);
    const payerCost = payerBefore - payerAfter;
    expect(payerCost).toBeGreaterThan(0n);
    expect(payerCost).toBeLessThan(BigInt(DEFAULT_MAX_FEE_DROPS));

    console.log(
      `[upto-xrpl.live] bare close on ${network}; channel=${channelId}; tx=${settle.transaction}`,
    );
  }, 240_000);
});
