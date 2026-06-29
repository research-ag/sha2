/// Allocation-free, single-shot SHA-256 hash engine for short, fixed-length
/// messages.
///
/// A `Hasher` is the lean counterpart of `Sha256.Digest`. A `Digest` carries a
/// message buffer so it can absorb a stream of writes of any length; a `Hasher`
/// has NO buffer — it IS just the 256-bit state — so it can only hash messages
/// whose length is fixed and known at the call site, where the padding is a
/// compile-time constant. That restriction is exactly what makes it fast: for a
/// one- or two-block message it skips all the buffer bookkeeping. The advantage
/// shrinks as messages grow (more compression blocks dominate), so the `Hasher`
/// targets the short-message cases — Merkle nodes, hash chains, commitments.
///
/// This module is SHA-256 only (no SHA-224): unlike the family-level
/// `Sha256`/`Sha512` `Digest` modules, a `Hasher` is tied to one concrete
/// algorithm, so there is no `Algorithm` argument and `new()` takes none.
///
/// Every function follows one uniform contract:
///
///   `f(self, ...operands)` overwrites `self` with `SHA256(operands...)`,
///   starting from the IV.
///
/// So `self` is always a pure destination, fully overwritten — there is no
/// "closed" state, no `reset`, and the value held at any time simply IS the most
/// recent digest. Any operand may alias `self` (the sources are read into
/// locals before `self` is written), which is what makes the in-place
/// `hashState(h, h)` fold and Merkle-style `combineState(h, h, sib)` safe.
///
/// The verbs come in three families, each over a `Blob` operand or a state
/// operand: `hash…` (one operand), `combine…` (a pair), and `load…` (copy a
/// finished 32-byte hash in verbatim, no hashing — the inverse of `readSum`,
/// used to park a precomputed leaf/peak or transfer one from a `Digest`).
///
/// ```motoko name=import
/// import Hasher "mo:sha2/Hasher/Sha256";
/// ```
///
/// Bridging from a `Digest`: a closed SHA-256 `Sha256.Digest`'s `state` field
/// has the same type as a `Hasher`, so `hasher.hashState(digest.state)` consumes
/// it with no copy. The caller is responsible for ensuring the digest is closed
/// and is SHA-256 (a `Hasher` only sees the bare state, so it cannot check), and
/// must treat `digest.state` as a read-only source only — never pass it as
/// `self`, which would corrupt the digest. The fully-checked (but allocating)
/// alternative is `hasher.hashBlob32(digest.readSum())`.

import Prim "mo:prim";

import State "../sha256/state";

module {
  let nat8ToNat16 = Prim.nat8ToNat16;
  let arrayToBlob = Prim.arrayToBlob;

  /// A `Hasher` IS a SHA-256 state: the 256-bit digest as 16 `Nat16`
  /// half-words. As a flat mutable array it can be reused across hashes with no
  /// allocation; the value it holds is always the most recent digest.
  public type Hasher = State.State; // = [var Nat16] of length 16

  /// Create a new `Hasher`. The 16 words are zero-initialized; the first
  /// `hash…`/`combine…` overwrites them from the IV, so there is no separate
  /// `reset`. Reading a never-hashed `Hasher` returns zeros.
  ///
  /// ```motoko include=import
  /// let hasher = Hasher.new();
  /// ```
  public func new() : Hasher {
    [var 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  };

  /// Hash a single 32-byte `Blob`: `self := SHA256(data)`. One compression
  /// block. Allocation-free.
  ///
  /// ```motoko include=import
  /// let hasher = Hasher.new();
  /// let leaf : Blob = "\00\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10\11\12\13\14\15\16\17\18\19\1a\1b\1c\1d\1e\1f";
  /// hasher.hashBlob32(leaf);
  /// let hash : Blob = hasher.readSum();
  /// ```
  ///
  /// Traps if `data` is not exactly 32 bytes.
  public func hashBlob32(self : Hasher, data : Blob) {
    assert data.size() == 32;
    // Load the 32 message bytes into the state words (big-endian half-word
    // pairs), then hash the state in place. `process_fold_block` hashes whatever
    // 32 bytes the state holds, so this yields SHA256(data).
    var i = 0;
    while (i < 16) {
      self[i] := nat8ToNat16(data[2 * i]) << 8 | nat8ToNat16(data[2 * i + 1]);
      i += 1;
    };
    self.process_fold_block(self);
  };

  /// Hash the 32-byte state of `src`: `self := SHA256(src)`. One compression
  /// block. Allocation-free, with no serialization round-trip — the 16 state
  /// words are read directly. `src` may be the same `Hasher` as `self`, which is
  /// the in-place re-hash (the "fold" used for iterated and double-SHA hashing).
  ///
  /// ```motoko include=import
  /// let hasher = Hasher.new();
  /// hasher.hashBlob32("\00\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10\11\12\13\14\15\16\17\18\19\1a\1b\1c\1d\1e\1f");
  /// hasher.hashState(hasher); // double SHA256 of the 32-byte message
  /// let doubleHash : Blob = hasher.readSum();
  /// ```
  public func hashState(self : Hasher, src : Hasher) {
    self.process_fold_block(src);
  };

  /// Combine two 32-byte `Blob`s: `self := SHA256(b1 ++ b2)` (a 64-byte
  /// message), without concatenating them. Two compression blocks. The leaf
  /// primitive of a Merkle tree. Allocation-free.
  ///
  /// ```motoko include=import
  /// let hasher = Hasher.new();
  /// let l0 : Blob = "\00\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10\11\12\13\14\15\16\17\18\19\1a\1b\1c\1d\1e\1f";
  /// let l1 : Blob = "\20\21\22\23\24\25\26\27\28\29\2a\2b\2c\2d\2e\2f\30\31\32\33\34\35\36\37\38\39\3a\3b\3c\3d\3e\3f";
  /// hasher.combineBlob32(l0, l1);
  /// let node : Blob = hasher.readSum();
  /// ```
  ///
  /// Traps if either blob is not exactly 32 bytes.
  public func combineBlob32(self : Hasher, b1 : Blob, b2 : Blob) {
    assert b1.size() == 32 and b2.size() == 32;
    self.process_leaf_block(b1, b2); // data block (b1 ++ b2) from the IV
    self.process_padding_block(512); // padding: 64-byte message = 512 bits
  };

  /// Combine the 32-byte states of two `Hasher`s: `self := SHA256(s1 ++ s2)` (a
  /// 64-byte message), reading the words directly with no `Blob`. Two
  /// compression blocks. The internal-node primitive of a Merkle tree. Either
  /// `s1` or `s2` may alias `self` (e.g. `combineState(node, node, sibling)` to
  /// move a peak up a level). Allocation-free.
  ///
  /// ```motoko include=import
  /// let left = Hasher.new();
  /// left.hashBlob32("\00\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10\11\12\13\14\15\16\17\18\19\1a\1b\1c\1d\1e\1f");
  /// let right = Hasher.new();
  /// right.hashBlob32("\20\21\22\23\24\25\26\27\28\29\2a\2b\2c\2d\2e\2f\30\31\32\33\34\35\36\37\38\39\3a\3b\3c\3d\3e\3f");
  /// left.combineState(left, right); // left := SHA256(left ++ right)
  /// let parent : Blob = left.readSum();
  /// ```
  public func combineState(self : Hasher, s1 : Hasher, s2 : Hasher) {
    self.process_merge_block(s1, s2); // data block (s1 ++ s2) from the IV
    self.process_padding_block(512); // padding: 64-byte message = 512 bits
  };

  /// Load a 32-byte hash into `self` VERBATIM — no hashing. The inverse of
  /// `readSum`: `readSum(self)` after `loadBlob32(self, b)` returns `b`. Unlike
  /// `hashBlob32` (which hashes its input), this just deposits the bytes as the
  /// state, so `self` becomes a peer "peak" you can feed to `combineState`. Use
  /// it to park a precomputed leaf/peak hash (e.g. one read back from storage)
  /// into the engine. Allocation-free.
  ///
  /// ```motoko include=import
  /// let hasher = Hasher.new();
  /// let leafHash : Blob = "\00\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10\11\12\13\14\15\16\17\18\19\1a\1b\1c\1d\1e\1f";
  /// hasher.loadBlob32(leafHash); // hasher now HOLDS leafHash (it is not re-hashed)
  /// let same : Blob = hasher.readSum(); // == leafHash
  /// ```
  ///
  /// Traps if `data` is not exactly 32 bytes.
  public func loadBlob32(self : Hasher, data : Blob) {
    assert data.size() == 32;
    var i = 0;
    while (i < 16) {
      self[i] := nat8ToNat16(data[2 * i]) << 8 | nat8ToNat16(data[2 * i + 1]);
      i += 1;
    };
  };

  /// Copy the 32-byte state of `src` into `self` VERBATIM — no hashing. The
  /// state-source sibling of `loadBlob32`: it transfers a finished hash from a
  /// `Digest` or another `Hasher` without re-hashing it. This is how a leaf lands
  /// in a `Hasher` for a SINGLE-SHA tree (`d.close()` then `loadState(h, d.state)`;
  /// the bridge `hashState` would add an unwanted second hash), and the general
  /// way to move any finished digest into a `Hasher`. Allocation-free.
  ///
  /// `src` may be a closed `Sha256.Digest`'s `state` (the caller ensures it is
  /// closed and SHA-256, as with the `hashState` bridge). It is read-only.
  ///
  /// ```motoko include=import
  /// let hasher = Hasher.new();
  /// let other = Hasher.new();
  /// other.hashBlob32("\00\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10\11\12\13\14\15\16\17\18\19\1a\1b\1c\1d\1e\1f");
  /// hasher.loadState(other); // hasher now holds the same hash as other
  /// ```
  public func loadState(self : Hasher, src : Hasher) {
    var i = 0;
    while (i < 16) {
      self[i] := src[i];
      i += 1;
    };
  };

  /// Read the current 32-byte digest as a `Blob`. Non-mutating — the state is
  /// always final, so this can be called any number of times. This is the only
  /// allocation in the API.
  ///
  /// ```motoko include=import
  /// let hasher = Hasher.new();
  /// hasher.hashBlob32("\00\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10\11\12\13\14\15\16\17\18\19\1a\1b\1c\1d\1e\1f");
  /// let hash : Blob = hasher.readSum();
  /// ```
  public func readSum(self : Hasher) : Blob {
    arrayToBlob(self.toNat8Array(32));
  };
};
