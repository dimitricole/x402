---
"@x402/xrpl": minor
---

XRPL exact scheme verification and settlement fixes:

- Add `SettlementStore` interface so horizontally scaled facilitators can back duplicate-settlement protection with a shared atomic store (for example Redis `SET NX PX`); the in-memory `SettlementCache` remains the single-process default.
- Size settlement-cache retention from the transaction's ledger window using a conservative per-ledger close-time bound instead of nominal wall-clock time.
- Normalize IOU currency codes to the binary codec's canonical form so 40-hex and 3-character representations of the same currency match.
- Behavior change: verification now rejects `requirements.maxTimeoutSeconds` above the facilitator's policy cap (new `maxTimeoutSeconds` option, default 3600) or non-positive/non-integer values, adding the `invalid_exact_xrpl_max_timeout_out_of_policy` reason.
- Client-built transactions sign `LastLedgerSequence` two ledgers below the facilitator's acceptance bound, tolerating ledger-view skew between client and facilitator nodes.
