/// Example: N-fold hashing (apply SHA repeatedly) with `mo:sha2`, allocation-free.
///
/// "N-fold" SHA256 means hashing the message, then hashing that digest, and so
/// on, N times:  H^N(msg) = H(H(...H(msg))).  N = 2 is the double SHA used by
/// Bitcoin (also available directly as `sumDouble`).
///
/// The tools are `close()` and `fold()`:
///   * `close()` finalizes the message, leaving the digest H1 in the state.
///   * `fold()` hashes the digest currently in the state (state -> SHA256(state))
///     in one specialized block, without ever producing a `Blob`.
///   * `readSum()` reads the finalized state out as a `Blob` (idempotent).
///
/// So a clean N-fold is:
///
///     digest.writeBlob(msg);
///     digest.close();     // H1 = SHA256(msg)
///     digest.fold();      // repeat (N - 1) times: H2, H3, ... HN
///     digest.readSum();   // read HN -> the result Blob
///
/// Only `readSum()` allocates (the digest you return). `close()` and every
/// `fold()` are allocation-free.
///
/// === Allocation-free for BULK hashing ===
///
/// When you hash MANY messages (or many items), the trap is allocating a fresh
/// hasher per item. Instead:
///
///   1. Allocate ONE hasher up front, outside the loop.
///   2. `reset()` it before each message — this rewinds it for reuse instead of
///      allocating a new one.
///   3. Feed input with `writeBlob` (allocation-free for word-aligned data).
///   4. `close()` once, then `fold()` for the remaining rounds, and `readSum()`
///      to read each message's final digest.
///
/// The only unavoidable allocations are the output digests themselves (one
/// `Blob` per message — the result you asked for). See `nfoldBatch` below.
///
/// Note: `fold()` is sha256-only (its fast block is size-specific), so these
/// examples use the default `#sha256` algorithm.

// In your own application, depend on the sha2 package and import it by name:
//   import Sha256 "mo:sha2/Sha256";
// These files live inside the sha2 repo, so they import the source directly.
import Sha256 "../src/Sha256";
import Array "mo:core/Array";

module {
  /// H^n(message): apply SHA256 `n` times (n >= 1). Allocates only the result.
  public func nfold(message : Blob, n : Nat) : Blob {
    assert n >= 1;
    let h = Sha256.new();
    h.writeBlob(message);
    h.close(); // H1 = SHA256(message)
    var k = 1;
    while (k < n) {
      h.fold(); // an inner round; runs (n - 1) times
      k += 1;
    };
    h.readSum(); // read the final hash -> the result Blob
  };

  /// N-fold-hash a whole batch of messages while reusing a single hasher, so
  /// the only allocations are the returned digests (one `Blob` per message).
  public func nfoldBatch(messages : [Blob], n : Nat) : [Blob] {
    assert n >= 1;
    let h = Sha256.new(); // allocated ONCE for the entire batch
    // Array.tabulate calls the function for index 0, 1, 2, ... in order, so it
    // is safe to share and rewind the one hasher between items.
    Array.tabulate<Blob>(
      messages.size(),
      func(j) {
        h.reset(); // rewind for the next message — no `Sha256.new()` per item
        h.writeBlob(messages[j]);
        h.close();
        var k = 1;
        while (k < n) {
          h.fold();
          k += 1;
        };
        h.readSum();
      },
    );
  };
};
