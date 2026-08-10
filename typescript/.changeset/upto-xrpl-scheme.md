---
"@x402/xrpl": minor
---

Add the `upto` payment scheme for XRPL, implementing `scheme_upto_xrpl.md` with Payment Channels: the client escrows the authorized maximum in a channel and signs one off-ledger claim, the resource server signs the settlement `PaymentChannelClaim` for the actual charge (`buildSettlementRequirements`), and the facilitator verifies both signatures and channel bindings against a validated ledger, relays the claim, and deduplicates settlements on `(network, channelId)`. New subpath exports `@x402/xrpl/upto/{client,server,facilitator}` and `createUptoXrplWalletSigner`. `XrplSettlementResult` gains an optional `meta` field, which the upto facilitator uses to confirm the delivered amount.
