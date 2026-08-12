import { SETTLEMENT_TTL_MS } from "./constants";

/**
 * In-memory cache for deduplicating concurrent settlement requests.
 *
 * XRPL transaction submission is idempotent on the transaction hash:
 * `submitAndWait` for an already-submitted hash resolves with the same
 * `tesSUCCESS` outcome instead of failing, so every concurrent `/settle`
 * call carrying the same signed blob would otherwise report success.
 * Because Node.js is single-threaded and the check + insert happens
 * synchronously inside one call, concurrent settle paths cannot
 * interleave within it and no lock is required.
 *
 * Unlike Solana, whose blockhash lifetime bounds the replay window at a
 * protocol-fixed ~60-90s, an XRPL transaction stays landable until its
 * `LastLedgerSequence`, which the scheme derives from the payment's
 * `maxTimeoutSeconds`. An entry must therefore be retained until its
 * transaction can no longer land, so callers pass a per-entry TTL sized
 * to that window; {@link SETTLEMENT_TTL_MS} is only the default floor.
 *
 * A scheme instance creates its own cache by default; pass a shared
 * instance to the constructor when several scheme instances should
 * block each other's duplicates. This is a per-process guard — a
 * horizontally scaled facilitator must back it with a shared atomic
 * store so duplicates routed to different replicas are still caught.
 */
export class SettlementCache {
  /** Maps a settlement key to its holder's token and eviction time (ms epoch). */
  private readonly entries = new Map<string, { token: number; expiresAt: number }>();
  private nextToken = 1;

  /**
   * Returns `true` if `key` is already pending settlement (duplicate),
   * or `false` after recording it as newly pending.
   *
   * Callers should reject the settlement when this returns `true`.
   *
   * @param key - The unique identifier for the settlement (the signed transaction hash).
   * @param ttlMs - How long to retain the entry, in milliseconds; must cover the
   *   transaction's landable window. Defaults to {@link SETTLEMENT_TTL_MS}.
   * @returns `true` if the key was already present (duplicate); `false` otherwise.
   */
  isDuplicate(key: string, ttlMs: number = SETTLEMENT_TTL_MS): boolean {
    return this.acquire(key, ttlMs) === undefined;
  }

  /**
   * Claims `key` for one settlement attempt.
   *
   * @param key - The unique identifier for the settlement.
   * @param ttlMs - How long to retain the entry, in milliseconds; must cover the
   *   transaction's landable window. Defaults to {@link SETTLEMENT_TTL_MS}.
   * @returns A token identifying this holder, or undefined when the key is held.
   */
  acquire(key: string, ttlMs: number = SETTLEMENT_TTL_MS): number | undefined {
    this.prune();
    if (this.entries.has(key)) {
      return undefined;
    }
    const token = this.nextToken++;
    this.entries.set(key, { token, expiresAt: Date.now() + ttlMs });
    return token;
  }

  /**
   * Returns whether `key` currently holds a live entry.
   *
   * @param key - The unique identifier to look up.
   * @returns `true` while an unexpired entry holds the key.
   */
  has(key: string): boolean {
    this.prune();
    return this.entries.has(key);
  }

  /**
   * Removes `key` unconditionally, regardless of holder.
   *
   * For supersession only: when another guard takes over the same identity
   * (a settlement entry superseding a verify-phase in-flight entry), the
   * displaced entry is deleted without a token. Everywhere else use
   * {@link release}, which cannot cancel another holder's protection.
   *
   * @param key - The unique identifier to remove.
   */
  evict(key: string): void {
    this.entries.delete(key);
  }

  /**
   * Releases a key claimed by {@link acquire}, re-allowing settlement.
   *
   * For a settlement whose submission definitively failed (a final result in
   * a validated ledger), retaining the entry would block every retry for the
   * full TTL while nothing ever landed. Callers release on definitive failure
   * and retain on success or on an ambiguous outcome (an exception
   * mid-submission may still land).
   *
   * The token makes the release the holder's own: if the entry has since been
   * evicted and re-claimed by another attempt, releasing must not cancel that
   * attempt's protection while its transaction may still be in flight.
   *
   * @param key - The unique identifier previously passed to {@link acquire}.
   * @param token - The token that {@link acquire} returned to this holder.
   */
  release(key: string, token: number): void {
    if (this.entries.get(key)?.token === token) {
      this.entries.delete(key);
    }
  }

  /**
   * Remove entries whose retention window has elapsed. Entries carry
   * heterogeneous TTLs, so every entry is checked rather than stopping at
   * the first live one; the cache only ever holds recently-seen settlements,
   * so this stays small.
   */
  private prune(): void {
    const now = Date.now();
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) {
        this.entries.delete(key);
      }
    }
  }
}
