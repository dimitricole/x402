import { describe, expect, it, vi } from "vitest";
import {
  ECDSA,
  PaymentChannelClaimFlags,
  Wallet,
  authorizeChannel,
  decode,
  dropsToXrp,
  encode,
  hashes,
  verifyPaymentChannelClaim,
  verifySignature,
} from "xrpl";
import { UptoXrplScheme as UptoXrplClientScheme } from "../../src/upto/client/scheme";
import { UptoXrplScheme as UptoXrplFacilitatorScheme } from "../../src/upto/facilitator/scheme";
import { UptoXrplScheme as UptoXrplServerScheme } from "../../src/upto/server/scheme";
import { createUptoXrplWalletSigner, createXrplWalletSigner } from "../../src/signer";
import {
  LANDING_MARGIN_SECONDS,
  SettlementCache,
  XRPL_MAINNET,
  XRPL_TESTNET,
  getPayChannel,
} from "../../src";
import type {
  PayChannelEntry,
  UptoXrplClientOptions,
  UptoXrplPayload,
  XrplFacilitatorOptions,
} from "../../src";
import type { PaymentPayload, PaymentRequirements } from "@x402/core/types";
import type { Client, PaymentChannelClaim, PaymentChannelCreate, TransactionMetadata } from "xrpl";

const payerWallet = Wallet.fromSeed("sEdTM1uX8pu2do5XvTnutH6HsouMaM2");
const payToWallet = Wallet.fromSeed("sEd7t79mzn2dwy3vvpvRmaaLbLhvme6");
const otherWallet = Wallet.fromSeed("sEdSJHS4oiAdz7w2X2ni1gFiqtbJHqE");
// secp256k1, for the signature-canonicality case.
const secpWallet = Wallet.fromSeed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb", {
  algorithm: ECDSA.secp256k1,
});
const payTo = payToWallet.classicAddress;

const CHANNEL = "C93B7DF84AC3F2C2BB69C88917451FA3980472DABEF8FFA461A0B1563BEF71AF";
const MAX_DROPS = "10000000";
const CLOSE_TIME = 800_000_000;
const CLOSE_TIME_UNIX = CLOSE_TIME + 946_684_800;
const CANCEL_AFTER = CLOSE_TIME + 86_400;
const CURRENT_LEDGER = 990;
const VALID_SIGNATURE = authorizeChannel(payerWallet, CHANNEL, MAX_DROPS);

const baseRequirements: PaymentRequirements = {
  scheme: "upto",
  network: XRPL_TESTNET,
  asset: "XRP",
  amount: MAX_DROPS,
  payTo,
  maxTimeoutSeconds: 300,
  extra: {
    areFeesSponsored: false,
    minSettleDelay: 60,
  },
} as unknown as PaymentRequirements;

function makeChannel(overrides: Partial<PayChannelEntry> = {}): PayChannelEntry {
  return {
    LedgerEntryType: "PayChannel",
    Account: payerWallet.classicAddress,
    Destination: payTo,
    Amount: MAX_DROPS,
    Balance: "0",
    PublicKey: payerWallet.publicKey,
    SettleDelay: 60,
    CancelAfter: CANCEL_AFTER,
    ...overrides,
  };
}

function makeRequirements(overrides: Record<string, unknown> = {}): PaymentRequirements {
  return {
    ...baseRequirements,
    ...overrides,
    extra: { ...(baseRequirements.extra as object), ...(overrides.extra as object | undefined) },
  } as unknown as PaymentRequirements;
}

function makePayload(
  payloadOverrides: Record<string, unknown> = {},
  accepted: PaymentRequirements = baseRequirements,
): PaymentPayload {
  return {
    x402Version: 2,
    accepted,
    payload: {
      channelId: CHANNEL,
      maxAmount: MAX_DROPS,
      signature: VALID_SIGNATURE,
      publicKey: payerWallet.publicKey,
      payer: payerWallet.classicAddress,
      ...payloadOverrides,
    },
  } as unknown as PaymentPayload;
}

function createFacilitator(
  overrides: XrplFacilitatorOptions = {},
  settlementCache?: SettlementCache,
): UptoXrplFacilitatorScheme {
  return new UptoXrplFacilitatorScheme(
    {
      getPayChannel: async () => makeChannel(),
      getLedgerCloseTime: async () => CLOSE_TIME,
      getCurrentLedgerIndex: async () => CURRENT_LEDGER,
      getAccountAuthorization: async () => ({ isMasterKeyDisabled: false }),
      submitSignedTransaction: async () => ({
        hash: "ABC",
        validated: true,
        resultCode: "tesSUCCESS",
      }),
      ...overrides,
    },
    settlementCache,
  );
}

function signSettlement(
  actual: string,
  overrides: Partial<PaymentChannelClaim> = {},
  signer: Wallet = payToWallet,
): string {
  const claimFields =
    actual === "0"
      ? {}
      : {
          Balance: actual,
          Amount: MAX_DROPS,
          Signature: VALID_SIGNATURE,
          PublicKey: payerWallet.publicKey,
        };
  const claim: PaymentChannelClaim = {
    TransactionType: "PaymentChannelClaim",
    Account: payTo,
    Channel: CHANNEL,
    Flags: PaymentChannelClaimFlags.tfClose,
    Fee: "12",
    Sequence: 1,
    LastLedgerSequence: 1_000,
    ...claimFields,
    ...overrides,
  };
  return signer.sign(claim).tx_blob;
}

function settleRequirements(actual: string, settlementTransaction?: string): PaymentRequirements {
  return makeRequirements({
    amount: actual,
    extra: {
      settlementTransaction: settlementTransaction ?? signSettlement(actual),
    },
  });
}

function claimMeta(finalBalance: string, channelId: string = CHANNEL): TransactionMetadata {
  return {
    AffectedNodes: [
      {
        DeletedNode: {
          LedgerEntryType: "PayChannel",
          LedgerIndex: channelId,
          FinalFields: { Balance: finalBalance },
        },
      },
    ],
    TransactionIndex: 0,
    TransactionResult: "tesSUCCESS",
  } as unknown as TransactionMetadata;
}

describe("UptoXrplScheme facilitator capabilities", () => {
  it("advertises the terms its own envelope check requires", async () => {
    const facilitator = createFacilitator();
    const extra = facilitator.getExtra(XRPL_TESTNET) as Record<string, unknown>;
    expect(extra).toEqual({ areFeesSponsored: false });

    // Drift between what is advertised and what is required would break every
    // payment, so verify the advertised terms actually verify.
    const requirements = makeRequirements({ extra });
    const result = await facilitator.verify(makePayload({}, requirements), requirements);
    expect(result.isValid).toBe(true);
  });

  it("advertises no facilitator signers", () => {
    expect(createFacilitator().getSigners(XRPL_TESTNET)).toEqual([]);
  });
});

describe("UptoXrplScheme facilitator verify", () => {
  it("accepts a valid authorization", async () => {
    const result = await createFacilitator().verify(makePayload(), baseRequirements);
    expect(result.isValid).toBe(true);
    expect(result.payer).toBe(payerWallet.classicAddress);
  });

  it("rejects a garbage claim signature", async () => {
    const result = await createFacilitator().verify(
      makePayload({ signature: "DEADBEEF".repeat(8) }),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_claim_signature");
  });

  it("rejects a claim signature over a different amount", async () => {
    const result = await createFacilitator().verify(
      makePayload({ signature: authorizeChannel(payerWallet, CHANNEL, "5000000") }),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_claim_signature");
  });

  it("rejects a claim signature from a different key", async () => {
    const result = await createFacilitator().verify(
      makePayload({ signature: authorizeChannel(otherWallet, CHANNEL, MAX_DROPS) }),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_claim_signature");
  });

  it("rejects a non-canonical high-s secp256k1 claim signature", async () => {
    const canonical = authorizeChannel(secpWallet, CHANNEL, MAX_DROPS);
    const facilitator = createFacilitator({
      getPayChannel: async () =>
        makeChannel({ Account: secpWallet.classicAddress, PublicKey: secpWallet.publicKey }),
    });
    const accepted = await facilitator.verify(
      makePayload({
        signature: canonical,
        publicKey: secpWallet.publicKey,
        payer: secpWallet.classicAddress,
      }),
      baseRequirements,
    );
    expect(accepted.isValid).toBe(true);

    const result = await facilitator.verify(
      makePayload({
        signature: toHighS(canonical),
        publicKey: secpWallet.publicKey,
        payer: secpWallet.classicAddress,
      }),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_claim_signature");
  });

  it("rejects a malformed payer as a malformed payload", async () => {
    const result = await createFacilitator().verify(
      makePayload({ payer: "not-an-address" }),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_payload");
  });

  it("rejects a malformed channel id as a malformed payload", async () => {
    const result = await createFacilitator().verify(
      makePayload({ channelId: "abc123" }),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_payload");
  });

  it("rejects accepted terms whose amount differs", async () => {
    const result = await createFacilitator().verify(
      makePayload({}, makeRequirements({ amount: "1" })),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_amount_mismatch");
  });

  it("rejects accepted terms whose payTo differs", async () => {
    const result = await createFacilitator().verify(
      makePayload({}, makeRequirements({ payTo: otherWallet.classicAddress })),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_pay_to_mismatch");
  });

  it("rejects requirements that do not disclaim fee sponsorship", async () => {
    const requirements = makeRequirements({ extra: { areFeesSponsored: undefined } });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_fees_sponsored_unsupported");
  });

  it("rejects accepted terms that claim fee sponsorship", async () => {
    // The accepted side must disclaim sponsorship on its own, not merely
    // match: a client cannot echo terms the scheme can never honor.
    const result = await createFacilitator().verify(
      makePayload({}, makeRequirements({ extra: { areFeesSponsored: true } })),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_fees_sponsored_unsupported");
  });

  it("rejects an already-drawn channel", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Balance: "1000" }),
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_channel_already_drawn");
  });

  it("accepts a channel with exactly the required headroom", async () => {
    // The work plus the landing that follows it: admitting anything less
    // would be admitting a payment that settlement must refuse.
    const result = await createFacilitator({
      getPayChannel: async () =>
        makeChannel({ CancelAfter: CLOSE_TIME + baseRequirements.maxTimeoutSeconds + 20 }),
    }).verify(makePayload(), baseRequirements);
    expect(result.isValid).toBe(true);
  });

  it("rejects a channel that cannot outlive the work plus its landing", async () => {
    const result = await createFacilitator({
      getPayChannel: async () =>
        makeChannel({ CancelAfter: CLOSE_TIME + baseRequirements.maxTimeoutSeconds + 19 }),
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_insufficient_time_bound");
  });

  it("rejects a settle delay too short for a claim to land", async () => {
    const requirements = makeRequirements({ extra: { minSettleDelay: undefined } });
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ SettleDelay: 19 }),
    }).verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_settle_delay_too_short");
  });

  it("admits only channels settlement will accept", async () => {
    // Every state verify admits must also be accepted at settle time:
    // anything admitted must still be settleable at the same ledger state,
    // or the metered work runs for nothing.
    for (const maxTimeoutSeconds of [1, 10, 20, 60, 300]) {
      for (const left of [1, 20, 21, 60, 320, 400]) {
        const requirements = makeRequirements({ maxTimeoutSeconds });
        const facilitator = createFacilitator({
          getPayChannel: async () => makeChannel({ CancelAfter: CLOSE_TIME + left }),
        });
        const verified = await facilitator.verify(makePayload({}, requirements), requirements);
        if (!verified.isValid) {
          continue;
        }
        const settled = await facilitator.settle(
          makePayload({}, requirements),
          makeRequirements({
            maxTimeoutSeconds,
            amount: "2500000",
            extra: { settlementTransaction: signSettlement("2500000") },
          }),
        );
        expect(settled.success).toBe(true);
      }
    }
  });

  it("rejects a channel with a pending close", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Expiration: CANCEL_AFTER }),
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_channel_closing");
  });

  it("rejects a time bound with too little settlement headroom", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ CancelAfter: CLOSE_TIME + 10 }),
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_channel_expired");
  });

  it("rejects a channel without a time bound", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ CancelAfter: undefined }),
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_missing_time_bound");
  });

  it("rejects a non-positive maxTimeoutSeconds", async () => {
    const requirements = makeRequirements({ maxTimeoutSeconds: -100 });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_max_timeout_seconds");
  });

  it("rejects a fractional maxTimeoutSeconds", async () => {
    const requirements = makeRequirements({ maxTimeoutSeconds: 1.5 });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_max_timeout_seconds");
  });

  it("rejects a destination that is not payTo", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Destination: otherWallet.classicAddress }),
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_destination_mismatch");
  });

  it("rejects a channel whose source is not the payer", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Account: otherWallet.classicAddress }),
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_payer_mismatch");
  });

  it("rejects an authorization below the required amount", async () => {
    const requirements = makeRequirements({ amount: "20000000" });
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Amount: "20000000" }),
    }).verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_max_amount_mismatch");
  });

  it("rejects an over-authorization, which could never settle", async () => {
    // settle() re-verifies with requirements.amount = maxAmount, and the
    // envelope requires accepted.amount to equal it, so a payload whose
    // maxAmount exceeds the required amount must fail at verify, not at
    // settle time after the metered work has run.
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Amount: "20000000" }),
    }).verify(
      makePayload({
        maxAmount: "20000000",
        signature: authorizeChannel(payerWallet, CHANNEL, "20000000"),
      }),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_max_amount_mismatch");
  });

  it("accepts a channel holding more than the authorized maximum", async () => {
    // PaymentChannelFund can raise Amount at any time; the signed claim, not
    // the deposit, is what caps settlement.
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Amount: "10000001" }),
    }).verify(makePayload(), baseRequirements);
    expect(result.isValid).toBe(true);
  });

  it("rejects an authorization above the channel amount", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Amount: "5000000" }),
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_authorization_exceeds_channel");
  });

  it("rejects a channel public key that differs from the payload", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ PublicKey: otherWallet.publicKey }),
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_public_key_mismatch");
  });

  it("rejects a non-XRP asset", async () => {
    const requirements = makeRequirements({ asset: "USD" });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_asset");
  });

  it("rejects a non-numeric required amount", async () => {
    const requirements = makeRequirements({ amount: "abc" });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_required_amount");
  });

  it("rejects a non-canonical required amount, which could never settle", async () => {
    // "0010000000" is BigInt-equal to maxAmount but not string-equal, and the
    // settle-time envelope compares strings: it would verify and then be
    // unsettleable for every actual amount.
    const requirements = makeRequirements({ amount: "0010000000" });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_required_amount");
  });

  it("rejects a non-canonical network id", async () => {
    const requirements = makeRequirements({ network: "xrpl:01" });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_network");
  });

  it("rejects a channel entry whose numeric fields are NaN", async () => {
    for (const field of ["SettleDelay", "CancelAfter"]) {
      const result = await createFacilitator({
        getPayChannel: async () => makeChannel({ [field]: NaN }),
      }).verify(makePayload(), baseRequirements);
      expect(result.invalidReason).toBe("invalid_upto_xrpl_channel_malformed");
    }
  });

  it("rejects a channel entry whose amounts are not drops", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Amount: "abc" }),
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_channel_malformed");
  });

  it("rejects a mismatched x402 version", async () => {
    const payload = makePayload();
    (payload as { x402Version: unknown }).x402Version = 1;
    const result = await createFacilitator().verify(payload, baseRequirements);
    expect(result.invalidReason).toBe("invalid_x402_version");
  });

  it("rejects a non-XRPL network", async () => {
    const requirements = makeRequirements({ network: "eip155:1" });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_network");
  });

  it("rejects accepted terms whose network differs", async () => {
    const result = await createFacilitator().verify(
      makePayload({}, makeRequirements({ network: XRPL_MAINNET })),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_network_mismatch");
  });

  it("rejects accepted terms whose asset differs", async () => {
    const result = await createFacilitator().verify(
      makePayload({}, makeRequirements({ asset: "USD" })),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_asset_mismatch");
  });

  it("rejects accepted terms whose maxTimeoutSeconds differs", async () => {
    const result = await createFacilitator().verify(
      makePayload({}, makeRequirements({ maxTimeoutSeconds: 600 })),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_max_timeout_mismatch");
  });

  it("rejects accepted terms whose minSettleDelay differs", async () => {
    const result = await createFacilitator().verify(
      makePayload({}, makeRequirements({ extra: { minSettleDelay: 30 } })),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_min_settle_delay_mismatch");
  });

  it("rejects accepted terms whose validAfter differs", async () => {
    const requirements = makeRequirements({ extra: { validAfter: CLOSE_TIME_UNIX - 60 } });
    const result = await createFacilitator().verify(
      makePayload({}, baseRequirements),
      requirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_valid_after_mismatch");
  });

  it("treats an explicit null optional extra as absent", async () => {
    // Other implementations marshal an absent optional as null; core
    // normalizes only the fields it owns, and `extra` is opaque.
    const requirements = makeRequirements({
      extra: { minSettleDelay: null, validAfter: null },
    });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.isValid).toBe(true);
  });

  it("rejects a malformed validAfter instead of skipping the check", async () => {
    const requirements = makeRequirements({ extra: { validAfter: -1 } });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_valid_after_malformed");
  });

  it("rejects an authorized maximum too large to convert, as a payload fault", async () => {
    const result = await createFacilitator().verify(
      makePayload({ maxAmount: "9".repeat(400) }),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_max_amount");
  });

  it("rejects a channel entry whose Expiration is not a number", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Expiration: NaN }),
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_channel_malformed");
  });

  it("rejects a non-numeric authorized maximum", async () => {
    const result = await createFacilitator().verify(
      makePayload({ maxAmount: "abc" }),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_max_amount");
  });

  it("rejects an authorized maximum beyond drops-to-XRP float precision", async () => {
    const collidingDrops = "8589934592000001";
    const requirements = makeRequirements({ amount: collidingDrops });
    const result = await createFacilitator().verify(
      makePayload({ maxAmount: collidingDrops }, requirements),
      requirements,
    );
    expect(result.invalidReason).toBe("invalid_upto_xrpl_max_amount");
  });

  it("rejects a malformed minSettleDelay instead of skipping the check", async () => {
    const requirements = makeRequirements({ extra: { minSettleDelay: "60" } });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_min_settle_delay_malformed");
  });

  it("rejects a settle delay below the required minimum", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ SettleDelay: 1 }),
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_settle_delay_too_short");
  });

  it("rejects a payment presented before validAfter", async () => {
    const requirements = makeRequirements({ extra: { validAfter: CLOSE_TIME_UNIX + 60 } });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_not_yet_valid");
  });

  it("accepts a payment presented after validAfter", async () => {
    const requirements = makeRequirements({ extra: { validAfter: CLOSE_TIME_UNIX - 60 } });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.isValid).toBe(true);
  });

  it("rejects a channel that does not exist", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => undefined,
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_channel_not_found");
  });

  it("reports a ledger read failure as a facilitator error, not a payload fault", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => {
        throw new Error("connection refused");
      },
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_facilitator_error");
    expect(result.invalidMessage).toContain("connection refused");
  });

  it("reports an unusable ledger close time as a facilitator error", async () => {
    // Every expiry comparison against NaN is false, so an unusable clock
    // would otherwise admit an expired channel.
    const result = await createFacilitator({
      getLedgerCloseTime: async () => Number.NaN,
    }).verify(makePayload(), baseRequirements);
    expect(result.invalidReason).toBe("invalid_upto_xrpl_facilitator_error");
  });

  it("rejects an unsupported scheme", async () => {
    const requirements = makeRequirements({ scheme: "exact" });
    const result = await createFacilitator().verify(makePayload({}, requirements), requirements);
    expect(result.invalidReason).toBe("unsupported_scheme");
  });

  it("rejects accepted terms whose scheme differs", async () => {
    const result = await createFacilitator().verify(
      makePayload({}, makeRequirements({ scheme: "exact" })),
      baseRequirements,
    );
    expect(result.invalidReason).toBe("unsupported_scheme");
  });
});

describe("UptoXrplScheme facilitator settle", () => {
  it("settles the actual amount with a payTo-signed claim", async () => {
    const result = await createFacilitator().settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(true);
    expect(result.transaction).toBe("ABC");
    expect(result.payer).toBe(payerWallet.classicAddress);
    expect(result.amount).toBe("2500000");
  });

  it("settles zero as a bare destination close", async () => {
    // A zero close is still an on-ledger transaction, so the response
    // carries its hash like any other settlement.
    const result = await createFacilitator().settle(makePayload(), settleRequirements("0"));
    expect(result.success).toBe(true);
    expect(result.transaction).toBe("ABC");
    expect(result.amount).toBe("0");
    expect(result.network).toBe(XRPL_TESTNET);
    expect(result.payer).toBe(payerWallet.classicAddress);
  });

  it("rejects a zero settlement that still carries claim fields", async () => {
    const blob = signSettlement("0", {
      Balance: "0",
      Amount: MAX_DROPS,
      Signature: VALID_SIGNATURE,
      PublicKey: payerWallet.publicKey,
    });
    const result = await createFacilitator().settle(makePayload(), settleRequirements("0", blob));
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
    expect(result.errorMessage).toContain("bare close");
  });

  it("rejects a settlement without a settlement transaction", async () => {
    const requirements = makeRequirements({ amount: "2500000" });
    const result = await createFacilitator().settle(makePayload(), requirements);
    expect(result.errorReason).toBe("invalid_upto_xrpl_missing_settlement_transaction");
  });

  it("rejects a settlement above the authorized maximum", async () => {
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("50000000", signSettlement("50000000", { Amount: "50000000" })),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_payload_settlement_exceeds_amount");
  });

  it("rejects a non-numeric settlement amount, keeping the payer", async () => {
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("not-a-number", signSettlement("2500000")),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_amount");
    expect(result.payer).toBe(payerWallet.classicAddress);
  });

  it("rejects a fractional settlement amount", async () => {
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("1.5", signSettlement("2500000")),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_amount");
  });

  it("rejects a claim whose Account is not payTo", async () => {
    const blob = signSettlement("2500000", { Account: otherWallet.classicAddress });
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
    expect(result.errorMessage).toContain("payTo");
  });

  it("rejects a claim whose Balance is not the settlement amount", async () => {
    const blob = signSettlement("2500000", { Balance: "2400000" });
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
    expect(result.errorMessage).toContain("Balance");
  });

  it("rejects a claim whose Amount is not the authorized maximum", async () => {
    const blob = signSettlement("2500000", { Amount: "9000000" });
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
    expect(result.errorMessage).toContain("authorized maximum");
  });

  it("rejects a claim without tfClose", async () => {
    const blob = signSettlement("2500000", { Flags: 0 });
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
    expect(result.errorMessage).toContain("tfClose");
  });

  it("rejects a claim whose LastLedgerSequence has already passed", async () => {
    const blob = signSettlement("2500000", { LastLedgerSequence: CURRENT_LEDGER });
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorMessage).toContain("already passed");
  });

  it("accepts the LastLedgerSequence xrpl.js autofill sets, at any timeout", async () => {
    // The bound must admit the fixed offset client.autofill() applies; see
    // XRPL_AUTOFILL_LEDGER_OFFSET.
    for (const maxTimeoutSeconds of [30, 60, 85, 300]) {
      const requirements = makeRequirements({
        maxTimeoutSeconds,
        amount: "2500000",
        extra: {
          settlementTransaction: signSettlement("2500000", {
            LastLedgerSequence: CURRENT_LEDGER + 20,
          }),
        },
      });
      const result = await createFacilitator().settle(
        makePayload({}, makeRequirements({ maxTimeoutSeconds })),
        requirements,
      );
      expect(result.success).toBe(true);
    }
  });

  it("rejects a claim landable beyond the settlement window", async () => {
    const blob = signSettlement("2500000", { LastLedgerSequence: CURRENT_LEDGER + 10_000 });
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorMessage).toContain("beyond the settlement window");
  });

  it("does not echo an attacker-supplied network in the response", async () => {
    const accepted = makeRequirements();
    (accepted as { network: unknown }).network = { evil: true };
    const result = await createFacilitator().settle(
      makePayload({}, accepted),
      settleRequirements("2500000"),
    );
    expect(result.success).toBe(false);
    expect(result.network).toBe(XRPL_TESTNET);
  });

  it("rejects a claim without LastLedgerSequence", async () => {
    const blob = signSettlement("2500000", { LastLedgerSequence: undefined });
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
    expect(result.errorMessage).toContain("LastLedgerSequence");
  });

  it("rejects a settlement transaction that is not a PaymentChannelClaim", async () => {
    const payment = payToWallet.sign({
      TransactionType: "Payment",
      Account: payTo,
      Destination: payerWallet.classicAddress,
      Amount: "1",
      Fee: "12",
      Sequence: 1,
      LastLedgerSequence: 1_000,
    }).tx_blob;
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", payment),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
    expect(result.errorMessage).toContain("not a PaymentChannelClaim");
  });

  it("rejects an undecodable settlement transaction", async () => {
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", "not-hex"),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
  });

  it("rejects an odd-length settlement blob rather than submitting unvalidated bytes", async () => {
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", `${signSettlement("2500000")}A`),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
  });

  it("rejects a claim whose Channel is not the payload channel", async () => {
    const blob = signSettlement("2500000", { Channel: CHANNEL.replace(/^C/, "D") });
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorMessage).toContain("Channel mismatch");
  });

  it("rejects a claim carrying NetworkID on a standard network", async () => {
    const blob = signSettlement("2500000", { NetworkID: 1 });
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorMessage).toContain("NetworkID");
  });

  it("accepts a claim carrying the NetworkID of a custom network", async () => {
    const accepted = makeRequirements({ network: "xrpl:1025" });
    const requirements = makeRequirements({
      network: "xrpl:1025",
      amount: "2500000",
      extra: { settlementTransaction: signSettlement("2500000", { NetworkID: 1025 }) },
    });
    const result = await createFacilitator().settle(makePayload({}, accepted), requirements);
    expect(result.success).toBe(true);
  });

  it("rejects a claim omitting NetworkID on a custom network", async () => {
    // A claim without NetworkID would be valid on every custom network at
    // once; rippled requires it above id 1024.
    const accepted = makeRequirements({ network: "xrpl:1025" });
    const requirements = makeRequirements({
      network: "xrpl:1025",
      amount: "2500000",
      extra: { settlementTransaction: signSettlement("2500000") },
    });
    const result = await createFacilitator().settle(makePayload({}, accepted), requirements);
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
    expect(result.errorMessage).toContain("NetworkID");
  });

  it("rejects a claim carrying tfRenew", async () => {
    const blob = signSettlement("2500000", {
      Flags: PaymentChannelClaimFlags.tfClose | PaymentChannelClaimFlags.tfRenew,
    });
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorMessage).toContain("tfRenew");
  });

  it("rejects a claim carrying a different payer claim signature", async () => {
    const blob = signSettlement("2500000", {
      Signature: authorizeChannel(payerWallet, CHANNEL, "2500000"),
    });
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorMessage).toContain("payer claim signature");
  });

  it("rejects a claim carrying a different channel public key", async () => {
    const blob = signSettlement("2500000", { PublicKey: otherWallet.publicKey });
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorMessage).toContain("PublicKey mismatch");
  });

  it("rejects a claim carrying Delegate, which routes around payTo authority", async () => {
    const blob = signSettlement("2500000");
    const decoded = decode(blob);
    decoded.Delegate = otherWallet.classicAddress;
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", encode(decoded)),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
    expect(result.errorMessage).toContain("Delegate");
  });

  it("rejects a multisigned claim", async () => {
    const blob = signSettlement("2500000");
    const decoded = decode(blob);
    decoded.Signers = [];
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", encode(decoded)),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
  });

  it("rejects a claim whose signing key is well-formed but not on the curve", async () => {
    const blob = signSettlement("2500000");
    const decoded = decode(blob);
    decoded.SigningPubKey = `02${"00".repeat(32)}`;
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", encode(decoded)),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
    expect(result.errorMessage).toContain("transaction signature invalid");
  });

  it("rejects a claim whose signing key is not in canonical form", async () => {
    // rippled rejects an uncompressed secp256k1 key at preflight; passing it
    // on would report an unsettleable claim as verified.
    const blob = signSettlement("2500000");
    const decoded = decode(blob);
    decoded.SigningPubKey = `04${"11".repeat(64)}`;
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", encode(decoded)),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");
    expect(result.errorMessage).toContain("non-canonical");
  });

  it("rejects a claim signed by the payTo master key when it is disabled", async () => {
    const result = await createFacilitator({
      getAccountAuthorization: async () => ({ isMasterKeyDisabled: true }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_signer_not_authorized");
  });

  it("re-verifies the channel bindings at settle time", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Destination: otherWallet.classicAddress }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.errorReason).toBe("invalid_upto_xrpl_destination_mismatch");
  });

  it("re-verifies the payer claim signature at settle time", async () => {
    // The wrong signature is mirrored into the blob, so the blob-binding
    // comparison cannot be what catches it: only the full signature
    // re-check over (channelId, maxAmount) can.
    const wrongSignature = authorizeChannel(payerWallet, CHANNEL, "10000001");
    const result = await createFacilitator().settle(
      makePayload({ signature: wrongSignature }),
      settleRequirements("2500000", signSettlement("2500000", { Signature: wrongSignature })),
    );
    expect(result.success).toBe(false);
    expect(result.errorReason).toBe("invalid_upto_xrpl_claim_signature");
  });

  it("re-verifies the channel public key at settle time", async () => {
    // The payload and blob agree on the substituted key; only the re-check
    // against the channel's own PublicKey can refuse it.
    const result = await createFacilitator().settle(
      makePayload({ publicKey: otherWallet.publicKey }),
      settleRequirements(
        "2500000",
        signSettlement("2500000", { PublicKey: otherWallet.publicKey }),
      ),
    );
    expect(result.success).toBe(false);
    expect(result.errorReason).toBe("invalid_upto_xrpl_public_key_mismatch");
  });

  it("settles over a channel the payer partly drew after verification", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Balance: "1" }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(true);
  });

  it("rejects a settlement the channel has already delivered", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Balance: "2500000" }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.errorReason).toBe("invalid_upto_xrpl_channel_already_drawn");
  });

  it("settles a channel whose pending close has not yet taken effect", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Expiration: CLOSE_TIME + 3_600 }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(true);
  });

  it("rejects a settlement on a channel whose close has taken effect", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ Expiration: CLOSE_TIME }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.errorReason).toBe("invalid_upto_xrpl_channel_expired");
  });

  it("settles a channel whose remaining headroom is under maxTimeoutSeconds", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ CancelAfter: CLOSE_TIME + 60 }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(true);
  });

  it("settles a channel with exactly the landing margin remaining", async () => {
    // The state verify's admission bound guarantees no more than this when
    // the metered work consumed its full maxTimeoutSeconds budget.
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ CancelAfter: CLOSE_TIME + LANDING_MARGIN_SECONDS }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(true);
  });

  it("rejects a settlement on a channel expiring before the claim can land", async () => {
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ CancelAfter: CLOSE_TIME + 5 }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.errorReason).toBe("invalid_upto_xrpl_channel_expired");
  });

  it("returns a complete response for a malformed accepted envelope", async () => {
    const payload = makePayload();
    (payload as { accepted: unknown }).accepted = undefined;
    const result = await createFacilitator().settle(payload, settleRequirements("2500000"));
    expect(result.success).toBe(false);
    expect(result.network).toBe(XRPL_TESTNET);
    expect(result.errorReason).toBe("invalid_upto_xrpl_payload");
  });

  it("rejects a claim signed by a key not authorized for payTo", async () => {
    const blob = signSettlement("2500000", {}, otherWallet);
    const result = await createFacilitator().settle(
      makePayload(),
      settleRequirements("2500000", blob),
    );
    expect(result.errorReason).toBe("invalid_upto_xrpl_settlement_signer_not_authorized");
  });

  it("accepts a claim signed by the payTo regular key", async () => {
    const blob = signSettlement("2500000", {}, otherWallet);
    const result = await createFacilitator({
      getAccountAuthorization: async () => ({
        regularKey: otherWallet.classicAddress,
        isMasterKeyDisabled: true,
      }),
    }).settle(makePayload(), settleRequirements("2500000", blob));
    expect(result.success).toBe(true);
  });

  it("reports an unvalidated submission result as a failure", async () => {
    const result = await createFacilitator({
      submitSignedTransaction: async () => ({
        hash: "ABC",
        validated: false,
        resultCode: "tesSUCCESS",
      }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(false);
    expect(result.errorReason).toBe("transaction_failed: tesSUCCESS");
  });

  it("preserves the payer and diagnostics when submission throws", async () => {
    const result = await createFacilitator({
      submitSignedTransaction: async () => {
        throw new Error("ECONNRESET");
      },
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(false);
    expect(result.errorReason).toBe("transaction_failed: ECONNRESET");
    expect(result.payer).toBe(payerWallet.classicAddress);
  });

  it("reports an unusable ledger index as a facilitator error", async () => {
    const result = await createFacilitator({
      getCurrentLedgerIndex: async () => Number.NaN,
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.errorReason).toBe("invalid_upto_xrpl_facilitator_error");
  });

  it("does not re-apply minSettleDelay once the work has run", async () => {
    // SettleDelay is fixed at PaymentChannelCreate; a claim the ledger
    // accepts must not be refused.
    const result = await createFacilitator({
      getPayChannel: async () => makeChannel({ SettleDelay: 30 }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(true);
  });

  it("confirms the delivered amount from claim metadata", async () => {
    const result = await createFacilitator({
      submitSignedTransaction: async () => ({
        hash: "ABC",
        validated: true,
        resultCode: "tesSUCCESS",
        meta: claimMeta("2500000"),
      }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(true);
  });

  it("rejects a claim that validated without delivering", async () => {
    // The metadata shows the channel's Balance untouched.
    const result = await createFacilitator({
      submitSignedTransaction: async () => ({
        hash: "ABC",
        validated: true,
        resultCode: "tesSUCCESS",
        meta: claimMeta("0"),
      }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(false);
    expect(result.errorReason).toBe("transaction_failed: channel_expired_before_claim");
    expect(result.transaction).toBe("ABC");
  });

  it("rejects a claim that validated without delivering, from a ModifiedNode", async () => {
    // The delivered-amount check reads a ModifiedNode the same as a
    // DeletedNode.
    const meta = {
      AffectedNodes: [
        {
          ModifiedNode: {
            LedgerEntryType: "PayChannel",
            LedgerIndex: CHANNEL,
            FinalFields: { Balance: "1000" },
          },
        },
      ],
      TransactionIndex: 0,
      TransactionResult: "tesSUCCESS",
    } as unknown as TransactionMetadata;
    const result = await createFacilitator({
      submitSignedTransaction: async () => ({
        hash: "ABC",
        validated: true,
        resultCode: "tesSUCCESS",
        meta,
      }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.errorReason).toBe("transaction_failed: channel_expired_before_claim");
  });

  it("treats metadata for a different channel as no delivery evidence", async () => {
    const result = await createFacilitator({
      submitSignedTransaction: async () => ({
        hash: "ABC",
        validated: true,
        resultCode: "tesSUCCESS",
        meta: claimMeta("0", CHANNEL.replace(/^C/, "D")),
      }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(true);
  });

  it("treats unreadable metadata as no delivery evidence", async () => {
    const result = await createFacilitator({
      submitSignedTransaction: async () => ({
        hash: "ABC",
        validated: true,
        resultCode: "tesSUCCESS",
        meta: { AffectedNodes: 42 } as unknown as TransactionMetadata,
      }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(true);
  });

  it("treats metadata without a final Balance as no delivery evidence", async () => {
    const meta = {
      AffectedNodes: [
        {
          DeletedNode: {
            LedgerEntryType: "PayChannel",
            LedgerIndex: CHANNEL,
            FinalFields: {},
          },
        },
      ],
      TransactionIndex: 0,
      TransactionResult: "tesSUCCESS",
    } as unknown as TransactionMetadata;
    const result = await createFacilitator({
      submitSignedTransaction: async () => ({
        hash: "ABC",
        validated: true,
        resultCode: "tesSUCCESS",
        meta,
      }),
    }).settle(makePayload(), settleRequirements("2500000"));
    expect(result.success).toBe(true);
  });

  it("does not demand delivery metadata for a zero settlement", async () => {
    // A bare close delivers nothing by design, expired or not.
    const result = await createFacilitator({
      submitSignedTransaction: async () => ({
        hash: "ABC",
        validated: true,
        resultCode: "tesSUCCESS",
        meta: claimMeta("0"),
      }),
    }).settle(makePayload(), settleRequirements("0"));
    expect(result.success).toBe(true);
  });
});

describe("UptoXrplScheme facilitator settlement dedup", () => {
  it("rejects a duplicate settlement on the same channel", async () => {
    const facilitator = createFacilitator();
    const requirements = settleRequirements("2500000");
    expect((await facilitator.settle(makePayload(), requirements)).success).toBe(true);
    const second = await facilitator.settle(makePayload(), requirements);
    expect(second.success).toBe(false);
    expect(second.errorReason).toBe("duplicate_settlement");
  });

  it("takes the dedup record only after every local check has passed", async () => {
    // A settlement refused before submission never held the channel, so a
    // corrected retry must not be told it is a duplicate.
    const facilitator = createFacilitator();
    const rejected = await facilitator.settle(
      makePayload(),
      settleRequirements(
        "2500000",
        signSettlement("2500000", { Channel: CHANNEL.replace(/^C/, "D") }),
      ),
    );
    expect(rejected.errorReason).toBe("invalid_upto_xrpl_settlement_transaction_mismatch");

    const retry = await facilitator.settle(makePayload(), settleRequirements("2500000"));
    expect(retry.errorReason).not.toBe("duplicate_settlement");
    expect(retry.success).toBe(true);
  });

  it("releases the dedup entry after a definitive submission failure", async () => {
    let resultCode = "tecNO_TARGET";
    const facilitator = createFacilitator({
      submitSignedTransaction: async () => ({ hash: "ABC", validated: true, resultCode }),
    });
    const requirements = settleRequirements("2500000");
    const first = await facilitator.settle(makePayload(), requirements);
    expect(first.errorReason).toBe("transaction_failed: tecNO_TARGET");

    resultCode = "tesSUCCESS";
    const retry = await facilitator.settle(makePayload(), requirements);
    expect(retry.success).toBe(true);
  });

  it("retains the dedup entry after an unvalidated submission result", async () => {
    // An unvalidated result means the node has reached no final outcome, so
    // the claim may still land: releasing here would let a second, larger
    // claim be drawn on the same channel.
    const submitted: string[] = [];
    let validated = false;
    const facilitator = createFacilitator({
      submitSignedTransaction: async blob => {
        submitted.push(blob);
        return { hash: "ABC", validated, resultCode: "tesSUCCESS" };
      },
    });
    const first = await facilitator.settle(makePayload(), settleRequirements("2500000"));
    expect(first.success).toBe(false);

    validated = true;
    const second = await facilitator.settle(makePayload(), settleRequirements(MAX_DROPS));
    expect(second.errorReason).toBe("duplicate_settlement");
    expect(submitted).toHaveLength(1);
  });

  it("retains the dedup entry after an ambiguous submission failure", async () => {
    let shouldThrow = true;
    const facilitator = createFacilitator({
      submitSignedTransaction: async () => {
        if (shouldThrow) {
          throw new Error("timeout");
        }
        return { hash: "ABC", validated: true, resultCode: "tesSUCCESS" };
      },
    });
    const requirements = settleRequirements("2500000");
    expect((await facilitator.settle(makePayload(), requirements)).success).toBe(false);

    shouldThrow = false;
    const retry = await facilitator.settle(makePayload(), requirements);
    expect(retry.errorReason).toBe("duplicate_settlement");
  });

  it("retains the dedup entry until the claim can no longer land", async () => {
    // The claim stays landable until its LastLedgerSequence, 30 ledgers out
    // at 10s each plus the 120s floor: 420s of retention. Probing at 200s,
    // past the bare floor but inside the derived window, distinguishes a TTL
    // sized from the claim's horizon from the default alone.
    vi.useFakeTimers();
    try {
      const facilitator = createFacilitator();
      const requirements = settleRequirements(
        "2500000",
        signSettlement("2500000", { LastLedgerSequence: CURRENT_LEDGER + 30 }),
      );
      expect((await facilitator.settle(makePayload(), requirements)).success).toBe(true);

      vi.advanceTimersByTime(200_000);
      const duringWindow = await facilitator.settle(makePayload(), requirements);
      expect(duringWindow.errorReason).toBe("duplicate_settlement");

      // Past the claim's horizon the entry has no claim left to protect.
      vi.advanceTimersByTime(221_000);
      const afterWindow = await facilitator.settle(makePayload(), requirements);
      expect(afterWindow.errorReason).not.toBe("duplicate_settlement");
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not let a stale holder release another attempt's dedup entry", async () => {
    // A settle whose entry has expired while it was still in flight must not
    // delete the entry a later attempt now holds: that later claim may still
    // land, and releasing would admit a third claim on the same channel.
    const cache = new SettlementCache();
    const key = `${XRPL_TESTNET}:${CHANNEL}`;
    const stale = cache.acquire(key, 1_000);
    expect(stale).toBeDefined();
    cache.release(key, stale as number);

    const current = cache.acquire(key, 1_000);
    expect(current).toBeDefined();
    cache.release(key, stale as number);
    expect(cache.acquire(key, 1_000)).toBeUndefined();
  });

  it("does not let channel id casing split the dedup key", async () => {
    const facilitator = createFacilitator();
    expect((await facilitator.settle(makePayload(), settleRequirements("2500000"))).success).toBe(
      true,
    );

    const lowercased = CHANNEL.toLowerCase();
    const result = await facilitator.settle(
      makePayload({ channelId: lowercased }),
      settleRequirements("2500000", signSettlement("2500000", { Channel: lowercased })),
    );
    expect(result.errorReason).toBe("duplicate_settlement");
  });

  it("does not block the same channel id across networks", async () => {
    const facilitator = createFacilitator();
    const testnet = await facilitator.settle(makePayload(), settleRequirements("2500000"));
    expect(testnet.success).toBe(true);

    const mainnetRequirements = makeRequirements({
      network: XRPL_MAINNET,
      amount: "2500000",
      extra: { settlementTransaction: signSettlement("2500000") },
    });
    const mainnetAccepted = makeRequirements({ network: XRPL_MAINNET });
    const mainnet = await facilitator.settle(makePayload({}, mainnetAccepted), mainnetRequirements);
    expect(mainnet.success).toBe(true);
  });

  it("serializes concurrent settles onto one submission", async () => {
    let submissions = 0;
    const facilitator = createFacilitator({
      submitSignedTransaction: async () => {
        submissions += 1;
        return { hash: "ABC", validated: true, resultCode: "tesSUCCESS" };
      },
    });
    const requirements = settleRequirements("2500000");
    const results = await Promise.all([
      facilitator.settle(makePayload(), requirements),
      facilitator.settle(makePayload(), requirements),
      facilitator.settle(makePayload(), requirements),
    ]);
    expect(results.filter(result => result.success)).toHaveLength(1);
    expect(submissions).toBe(1);
  });
});

describe("UptoXrplScheme server", () => {
  const supportedKind = { x402Version: 2, scheme: "upto", network: XRPL_TESTNET } as const;

  function createServer(): UptoXrplServerScheme {
    return new UptoXrplServerScheme(createXrplWalletSigner(payToWallet), {
      prepareSettlementTransaction: async transaction => ({
        ...transaction,
        Sequence: 1,
        Fee: "12",
        LastLedgerSequence: CURRENT_LEDGER + 20,
      }),
    });
  }

  it("parses explicit XRP asset amounts", async () => {
    const parsed = await createServer().parsePrice(
      { amount: MAX_DROPS, asset: "XRP" },
      XRPL_TESTNET,
    );
    expect(parsed).toEqual({ amount: MAX_DROPS, asset: "XRP", extra: {} });
  });

  it("rejects non-XRP pricing", async () => {
    await expect(
      createServer().parsePrice({ amount: "10.5", asset: "USD" }, XRPL_TESTNET),
    ).rejects.toThrow("XRP only");
  });

  it("rejects money pricing without a registered parser", async () => {
    await expect(createServer().parsePrice("$0.10", XRPL_TESTNET)).rejects.toThrow(
      "explicit AssetAmount",
    );
  });

  it("discloses unsponsored fees in enhanced requirements", async () => {
    const enhanced = await createServer().enhancePaymentRequirements(
      makeRequirements({ extra: { areFeesSponsored: undefined } }),
      supportedKind,
      [],
    );
    expect(enhanced.extra?.areFeesSponsored).toBe(false);
  });

  it("refuses a challenge that already carries a settlement transaction", () => {
    // Spec: extra.settlementTransaction MUST be absent from PAYMENT-REQUIRED,
    // and the resource server is the party that emits that header.
    expect(() =>
      createServer().enhancePaymentRequirements(
        makeRequirements({ extra: { settlementTransaction: signSettlement("1") } }),
        supportedKind,
        [],
      ),
    ).toThrow("absent from PAYMENT-REQUIRED");
  });

  it("rejects a malformed minSettleDelay when enhancing requirements", () => {
    expect(() =>
      createServer().enhancePaymentRequirements(
        makeRequirements({ extra: { minSettleDelay: "60" } }),
        supportedKind,
        [],
      ),
    ).toThrow("minSettleDelay");
  });

  it("signs a settlement claim carrying the payment's bindings", async () => {
    const settleReqs = await createServer().buildSettlementRequirements(
      makePayload(),
      makeRequirements({ amount: "2470000" }),
    );
    const blob = settleReqs.extra?.settlementTransaction as string;
    const claim = decode(blob) as unknown as PaymentChannelClaim;
    expect(claim.TransactionType).toBe("PaymentChannelClaim");
    expect(claim.Account).toBe(payTo);
    expect(claim.Channel).toBe(CHANNEL);
    expect(claim.Balance).toBe("2470000");
    expect(claim.Amount).toBe(MAX_DROPS);
    expect(claim.Signature?.toUpperCase()).toBe(VALID_SIGNATURE.toUpperCase());
    expect(claim.PublicKey?.toUpperCase()).toBe(payerWallet.publicKey.toUpperCase());
    expect((claim.Flags as number) & PaymentChannelClaimFlags.tfClose).not.toBe(0);
    expect((claim.Flags as number) & PaymentChannelClaimFlags.tfRenew).toBe(0);
    expect(claim.NetworkID).toBeUndefined();
    expect(verifySignature(blob)).toBe(true);
    expect(settleReqs.amount).toBe("2470000");
  });

  it("signs a zero settlement as a bare close", async () => {
    const settleReqs = await createServer().buildSettlementRequirements(
      makePayload(),
      makeRequirements({ amount: "0" }),
    );
    const claim = decode(
      settleReqs.extra?.settlementTransaction as string,
    ) as unknown as PaymentChannelClaim;
    expect(claim.Balance).toBeUndefined();
    expect(claim.Amount).toBeUndefined();
    expect(claim.Signature).toBeUndefined();
    expect(claim.PublicKey).toBeUndefined();
    expect((claim.Flags as number) & PaymentChannelClaimFlags.tfClose).not.toBe(0);
  });

  it("refuses to sign above the authorized maximum", async () => {
    await expect(
      createServer().buildSettlementRequirements(
        makePayload(),
        makeRequirements({ amount: "10000001" }),
      ),
    ).rejects.toThrow("authorized maximum");
  });

  it("refuses a non-canonical settlement amount", async () => {
    await expect(
      createServer().buildSettlementRequirements(
        makePayload(),
        makeRequirements({ amount: "02470000" }),
      ),
    ).rejects.toThrow("canonical");
  });

  it("refuses a malformed payment payload", async () => {
    await expect(
      createServer().buildSettlementRequirements(
        makePayload({ channelId: "abc" }),
        makeRequirements({ amount: "2470000" }),
      ),
    ).rejects.toThrow("malformed");
  });

  it("requires the prepared claim to carry LastLedgerSequence", async () => {
    // The facilitator bounds the claim's landable window from this field.
    const server = new UptoXrplServerScheme(createXrplWalletSigner(payToWallet), {
      prepareSettlementTransaction: async transaction => ({
        ...transaction,
        Sequence: 1,
        Fee: "12",
      }),
    });
    await expect(
      server.buildSettlementRequirements(makePayload(), makeRequirements({ amount: "2470000" })),
    ).rejects.toThrow("LastLedgerSequence");
  });
});

describe("UptoXrplScheme client", () => {
  function createClient(
    submitted: string[],
    options: UptoXrplClientOptions = {},
  ): UptoXrplClientScheme {
    return new UptoXrplClientScheme(createUptoXrplWalletSigner(payerWallet), {
      getLedgerCloseTime: async () => CLOSE_TIME,
      prepareChannelCreateTransaction: async transaction => ({
        ...transaction,
        Sequence: 7,
        Fee: "12",
        LastLedgerSequence: CURRENT_LEDGER + 20,
      }),
      submitSignedTransaction: async blob => {
        submitted.push(blob);
        return { hash: "DEF", validated: true, resultCode: "tesSUCCESS" };
      },
      ...options,
    });
  }

  it("escrows the maximum and signs a claim over the created channel", async () => {
    const submitted: string[] = [];
    const result = await createClient(submitted).createPaymentPayload(2, baseRequirements);

    const create = decode(submitted[0]) as unknown as PaymentChannelCreate;
    expect(create.TransactionType).toBe("PaymentChannelCreate");
    expect(create.Account).toBe(payerWallet.classicAddress);
    expect(create.Destination).toBe(payTo);
    expect(create.Amount).toBe(MAX_DROPS);
    expect(create.SettleDelay).toBe(60);
    expect(create.CancelAfter).toBe(
      CLOSE_TIME + baseRequirements.maxTimeoutSeconds + 3 * LANDING_MARGIN_SECONDS,
    );
    expect(create.PublicKey.toUpperCase()).toBe(payerWallet.publicKey.toUpperCase());
    expect(create.NetworkID).toBeUndefined();

    const payload = result.payload as UptoXrplPayload;
    expect(payload.channelId).toBe(hashes.hashPaymentChannel(payerWallet.classicAddress, payTo, 7));
    expect(payload.maxAmount).toBe(MAX_DROPS);
    expect(payload.payer).toBe(payerWallet.classicAddress);
    expect(payload.publicKey).toBe(payerWallet.publicKey);
    expect(
      verifyPaymentChannelClaim(
        payload.channelId,
        dropsToXrp(payload.maxAmount).toString(),
        payload.signature,
        payload.publicKey,
      ),
    ).toBe(true);
  });

  it("uses the landing margin when no minSettleDelay is required", async () => {
    const submitted: string[] = [];
    const requirements = makeRequirements({ extra: { minSettleDelay: undefined } });
    await createClient(submitted).createPaymentPayload(2, requirements);
    const create = decode(submitted[0]) as unknown as PaymentChannelCreate;
    expect(create.SettleDelay).toBe(LANDING_MARGIN_SECONDS);
  });

  it("rejects a failed channel create", async () => {
    const client = createClient([], {
      submitSignedTransaction: async () => ({
        hash: "DEF",
        validated: true,
        resultCode: "tecUNFUNDED_PAYMENT",
      }),
    });
    await expect(client.createPaymentPayload(2, baseRequirements)).rejects.toThrow(
      "tecUNFUNDED_PAYMENT",
    );
  });

  it("rejects requirements that do not disclaim fee sponsorship", async () => {
    const requirements = makeRequirements({ extra: { areFeesSponsored: undefined } });
    await expect(createClient([]).createPaymentPayload(2, requirements)).rejects.toThrow(
      "areFeesSponsored",
    );
  });

  it("rejects a non-canonical maximum amount", async () => {
    const requirements = makeRequirements({ amount: "0010000000" });
    await expect(createClient([]).createPaymentPayload(2, requirements)).rejects.toThrow(
      "canonical",
    );
  });

  it("requires the prepared create to carry NetworkID on a custom network", async () => {
    // Above id 1024 rippled binds transactions to the network; a prepare
    // hook that drops the field would open the channel on the wrong chain.
    const requirements = makeRequirements({ network: "xrpl:1025" });
    const client = createClient([], {
      prepareChannelCreateTransaction: async ({ NetworkID: _omitted, ...transaction }) => ({
        ...transaction,
        Sequence: 7,
        Fee: "12",
        LastLedgerSequence: CURRENT_LEDGER + 20,
      }),
    });
    await expect(client.createPaymentPayload(2, requirements)).rejects.toThrow(
      "must set NetworkID for custom XRPL networks",
    );
  });

  it("requires a plain sequence, which the channel id derives from", async () => {
    const client = createClient([], {
      prepareChannelCreateTransaction: async transaction => ({
        ...transaction,
        Sequence: 0,
        TicketSequence: 7,
        Fee: "12",
        LastLedgerSequence: CURRENT_LEDGER + 20,
      }),
    });
    await expect(client.createPaymentPayload(2, baseRequirements)).rejects.toThrow(
      "account Sequence",
    );
  });
});

describe("upto XRPL end to end", () => {
  it("settles a payment produced by the client and signed by the server", async () => {
    const channels = new Map<string, PayChannelEntry>();

    const clientScheme = new UptoXrplClientScheme(createUptoXrplWalletSigner(payerWallet), {
      getLedgerCloseTime: async () => CLOSE_TIME,
      prepareChannelCreateTransaction: async transaction => ({
        ...transaction,
        Sequence: 42,
        Fee: "12",
        LastLedgerSequence: CURRENT_LEDGER + 20,
      }),
      submitSignedTransaction: async blob => {
        // The ledger seam derives the channel from the submitted blob itself.
        const create = decode(blob) as unknown as PaymentChannelCreate;
        const channelId = hashes.hashPaymentChannel(
          create.Account,
          create.Destination,
          create.Sequence as number,
        );
        channels.set(channelId, {
          LedgerEntryType: "PayChannel",
          Account: create.Account,
          Destination: create.Destination,
          Amount: create.Amount as string,
          Balance: "0",
          PublicKey: create.PublicKey,
          SettleDelay: create.SettleDelay,
          CancelAfter: create.CancelAfter,
        });
        return { hash: "CREATE", validated: true, resultCode: "tesSUCCESS" };
      },
    });

    const serverScheme = new UptoXrplServerScheme(createXrplWalletSigner(payToWallet), {
      prepareSettlementTransaction: async transaction => ({
        ...transaction,
        Sequence: 9,
        Fee: "12",
        LastLedgerSequence: CURRENT_LEDGER + 20,
      }),
    });

    const facilitator = new UptoXrplFacilitatorScheme({
      getPayChannel: async channelId => channels.get(channelId.toUpperCase()),
      getLedgerCloseTime: async () => CLOSE_TIME,
      getCurrentLedgerIndex: async () => CURRENT_LEDGER,
      getAccountAuthorization: async () => ({ isMasterKeyDisabled: false }),
      submitSignedTransaction: async blob => {
        const claim = decode(blob) as unknown as PaymentChannelClaim;
        const channelId = claim.Channel.toUpperCase();
        const channel = channels.get(channelId);
        if (!channel) {
          return { hash: "CLAIM", validated: true, resultCode: "tecNO_TARGET" };
        }
        channels.delete(channelId);
        return {
          hash: "CLAIM",
          validated: true,
          resultCode: "tesSUCCESS",
          meta: claimMeta(claim.Balance ?? channel.Balance, channelId),
        };
      },
    });

    const created = await clientScheme.createPaymentPayload(2, baseRequirements);
    const paymentPayload = {
      x402Version: created.x402Version,
      accepted: baseRequirements,
      payload: created.payload,
    } as unknown as PaymentPayload;

    const verified = await facilitator.verify(paymentPayload, baseRequirements);
    expect(verified.isValid).toBe(true);

    const settleReqs = await serverScheme.buildSettlementRequirements(
      paymentPayload,
      makeRequirements({ amount: "2470000" }),
    );
    const settled = await facilitator.settle(paymentPayload, settleReqs);
    expect(settled.success).toBe(true);
    expect(settled.transaction).toBe("CLAIM");
    expect(settled.amount).toBe("2470000");
    expect(settled.payer).toBe(payerWallet.classicAddress);

    // The close consumed the channel, so a repeat settlement finds nothing.
    const duplicate = await facilitator.settle(paymentPayload, settleReqs);
    expect(duplicate.success).toBe(false);
    expect(duplicate.errorReason).toBe("invalid_upto_xrpl_channel_not_found");
  });
});

describe("XRPL upto utilities", () => {
  function fakeLedgerEntryClient(response: () => unknown): XrplFacilitatorOptions {
    return {
      clientFactory: () =>
        ({
          connect: async () => {},
          disconnect: async () => {},
          request: async () => response(),
        }) as unknown as Client,
    };
  }

  it("getPayChannel rejects a ledger entry that is not a PayChannel", async () => {
    const escrow = { ...makeChannel(), LedgerEntryType: "Escrow" };
    const channel = await getPayChannel(
      CHANNEL,
      XRPL_TESTNET,
      fakeLedgerEntryClient(() => ({ result: { node: escrow } })),
    );
    expect(channel).toBeUndefined();
  });

  it("getPayChannel returns undefined only for a missing entry", async () => {
    const notFound = Object.assign(new Error("entryNotFound"), {
      data: { error: "entryNotFound" },
    });
    const channel = await getPayChannel(
      CHANNEL,
      XRPL_TESTNET,
      fakeLedgerEntryClient(() => {
        throw notFound;
      }),
    );
    expect(channel).toBeUndefined();
  });

  it("getPayChannel propagates transport errors", async () => {
    await expect(
      getPayChannel(
        CHANNEL,
        XRPL_TESTNET,
        fakeLedgerEntryClient(() => {
          throw new Error("socket hang up");
        }),
      ),
    ).rejects.toThrow("socket hang up");
  });
});

/**
 * Re-encodes a canonical secp256k1 DER claim signature with s' = n - s.
 *
 * The high-s variant still satisfies generic ECDSA verification unless the
 * verifier enforces low-s; rippled rejects it, so verify() must too.
 *
 * @param signatureHex - Canonical DER signature in hex
 * @returns The high-s DER signature in hex
 */
function toHighS(signatureHex: string): string {
  const CURVE_ORDER = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
  const bytes = Buffer.from(signatureHex, "hex");
  const rLength = bytes[3];
  const sOffset = 4 + rLength + 2;
  const sLength = bytes[sOffset - 1];
  const s = BigInt(`0x${bytes.subarray(sOffset, sOffset + sLength).toString("hex")}`);
  let highS = (CURVE_ORDER - s).toString(16);
  if (highS.length % 2 === 1) {
    highS = `0${highS}`;
  }
  if (parseInt(highS.slice(0, 2), 16) >= 0x80) {
    highS = `00${highS}`;
  }
  const rPart = bytes.subarray(2, 4 + rLength);
  const sBytes = Buffer.from(highS, "hex");
  const body = Buffer.concat([rPart, Buffer.from([0x02, sBytes.length]), sBytes]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body])
    .toString("hex")
    .toUpperCase();
}
