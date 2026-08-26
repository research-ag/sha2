/// Example: N-fold hashing (apply SHA repeatedly) with `mo:sha2`, allocation-free.
///
/// "N-fold" SHA256 means hashing the message, then hashing that digest, and so
/// on, N times:  H^N(msg) = H(H(...H(msg))).  N = 2 is the double SHA used by
/// Bitcoin (also available directly as `Sha256.sumDouble`).
///
/// This example also showcases the `Digest` → `Hasher` BRIDGE — the "expert
/// path" for feeding a finished digest straight into the single-shot `Hasher`
/// with no intermediate `Blob`. It works because a `Digest`'s `state` field has
/// the same type as a `Hasher` (both are the 256-bit state), so a CLOSED sha256
/// digest's state can be handed directly to `Hasher.hashState`:
///
///   * `Digest` absorbs the arbitrary-length message (it has the buffer), then
///     `close()` leaves H1 = SHA256(msg) in its state.
///   * `h.hashState(digest.state)` reads those 32 bytes directly and
///     computes H2 = SHA256(H1) — no `Blob` materialized.
///   * `h.hashState(h)` then folds in place for each further round.
///
/// Caveats of the bridge (the `Hasher` only sees the bare state, so YOU must
/// guarantee these): the digest must be CLOSED, and it must be sha256 (not
/// sha224). Treat `digest.state` as a read-only source — never pass it as the
/// `Hasher`'s `self`, which would corrupt the digest.
///
/// Only `readSum()` allocates (the digest you return); `close()` and every
/// `hashState` are allocation-free.
///
/// === Allocation-free for BULK hashing ===
///
/// When you hash MANY messages, the trap is allocating a fresh engine per item.
/// Instead allocate ONE `Digest` and ONE `Hasher` up front and reuse them:
/// `reset()` the digest before each message, absorb with `writeBlob`, `close()`,
/// then bridge into the hasher for the folds. The only unavoidable allocations
/// are the output digests themselves (one `Blob` per message). See `nfoldBatch`.
///
/// Note: the fold is sha256-only (its fast block is size-specific), so these
/// examples use the default `#sha256` algorithm.

import Sha256 "mo:sha2/Sha256";
import Hasher "mo:sha2/Hasher/Sha256";
import Array "mo:core/Array";

module {
  /// H^n(message): apply SHA256 `n` times (n >= 1). Allocates only the result.
  public func nfold(message : Blob, n : Nat) : Blob {
    assert n >= 1;
    let d = Sha256.new();
    d.writeBlob(message);
    d.close(); // H1 = SHA256(message), now in d.state
    if (n == 1) return d.readSum();
    // Bridge: hand the closed digest's state straight to a Hasher (no Blob).
    let h = Hasher.new();
    h.hashState(d.state); // H2 = SHA256(H1)
    var k = 2;
    while (k < n) {
      h.hashState(h); // an inner round; runs (n - 2) more times -> H3 ... Hn
      k += 1;
    };
    h.readSum(); // read the final hash -> the result Blob
  };

  /// N-fold-hash a whole batch of messages while reusing a single `Digest` and a
  /// single `Hasher`, so the only allocations are the returned digests (one
  /// `Blob` per message).
  public func nfoldBatch(messages : [Blob], n : Nat) : [Blob] {
    assert n >= 1;
    let d = Sha256.new(); // both engines allocated ONCE for the whole batch
    let h = Hasher.new();
    // Array.tabulate calls the function for index 0, 1, 2, ... in order, so it
    // is safe to share and rewind the engines between items.
    Array.tabulate<Blob>(
      messages.size(),
      func(j) {
        d.reset(); // rewind the digest — no `Sha256.new()` per item
        d.writeBlob(messages[j]);
        d.close();
        if (n == 1) return d.readSum();
        h.hashState(d.state); // H2, bridged from the digest's state
        var k = 2;
        while (k < n) {
          h.hashState(h);
          k += 1;
        };
        h.readSum();
      },
    );
  };
};
