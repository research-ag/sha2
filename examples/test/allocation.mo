// @testmode wasi

// Asserts the allocation claims of the examples: adding leaves allocates
// nothing, a root readout allocates only the root Blob, the coinbase witness
// costs one Blob per spine level over the whole build, and the N-fold rounds
// are allocation-free.
//
// `Prim.rts_total_allocation()` is a monotonic counter of all bytes ever
// allocated, so its delta around a section is exactly what the section
// allocated. It is maintained only in compiled wasm, hence wasi test mode.
// Run from examples/ with `mops test allocation` (no `.test.mo` suffix, so the
// root project's `mops test` does not pick it up; see verify.mo).
//
// Sizes are those of the 64-bit heap (moc 2.0.0): an object header is 3 words
// (tag, forwarding pointer, length), so a 32-byte Blob takes 56 bytes and an
// array of n elements 24 + 8 * n bytes. The harness checks below pin this.

import MerkleStack "../MerkleStack";
import MerkleStackState "../MerkleStackState";
import MerkleCounter "../MerkleCounter";
import MerkleCounterState "../MerkleCounterState";
import BitcoinMerkle "../BitcoinMerkle";
import BitcoinTxMerkle "../BitcoinTxMerkle";
import BitcoinWitness "../BitcoinWitness";
import NFold "../NFold";
import Hasher "mo:sha2/Hasher/Sha256";
import Sha256 "mo:sha2/Sha256";
import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Seiran128 "mo:prng/Seiran128";
import Prim "mo:prim";

let rng = Seiran128.new();
rng.init(0x5eed);
func bytes(n : Nat) : Blob = Array.tabulate<Nat8>(n, func(_) = (rng.next() & 0xff).toNat8()).toBlob();

// Bytes allocated by `f`.
func alloc(f : () -> ()) : Nat {
  let before = Prim.rts_total_allocation();
  f();
  Prim.rts_total_allocation() - before;
};

func check(name : Text, actual : Nat, expected : Nat) {
  if (actual != expected) {
    Prim.debugPrint(name # ": allocated " # actual.toText() # " bytes, expected " # expected.toText());
    assert false;
  };
};

// --- Harness validation ---

check("empty loop", alloc(func() { var i = 0; while (i < 1000) { i += 1 } }), 0);
// A `for ... in Nat.range` loop allocates its iterator, so the measured
// sections below use `while` loops.
assert alloc(func() { for (_ in Nat.range(0, 1)) {} }) > 0;
assert alloc(func() { ignore Prim.Array_init<Nat>(8, 0) }) > 0;

let blob32 = 56; // a 32-byte Blob: 24-byte header + 32 bytes
func arrayBytes(n : Nat) : Nat = 24 + 8 * n;
// A hash readout (`readSum`) builds the 32 bytes as a `[Nat8]` first and then
// the Blob from it, so it allocates both; the array is garbage right away.
let readout = arrayBytes(32) + blob32;
do {
  let h = Hasher.new();
  h.hashBlob32(bytes(32));
  check("array of 5", alloc(func() { ignore Prim.Array_init<Nat>(5, 0) }), arrayBytes(5));
  check("one readSum", alloc(func() { ignore h.readSum() }), readout);
};

// Leaf counts: powers of two and their neighbors, up to 1000.
let ns = [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 100, 255, 256, 257, 1000];
let maxN = 1000;
let leaves = Array.tabulate<Blob>(maxN, func(_) = bytes(32));
// Raw messages of varying length, across block boundaries (64 bytes).
let msgs = Array.tabulate<Blob>(maxN, func(j) = bytes((j * 37) % 200));

// --- Trees over 32-byte Blob leaves ---

for (n in ns.values()) {
  let suffix = " (n = " # n.toText() # ")";
  // The root of a single leaf is the leaf itself, returned without a copy.
  let rootBytes = if (n == 1) 0 else readout;

  let s = MerkleStack.new(maxN);
  check("MerkleStack.add" # suffix, alloc(func() { var j = 0; while (j < n) { s.add(leaves[j]); j += 1 } }), 0);
  check("MerkleStack.root" # suffix, alloc(func() { ignore s.root() }), rootBytes);

  let c = MerkleCounter.new(maxN);
  check("MerkleCounter.add" # suffix, alloc(func() { var j = 0; while (j < n) { MerkleCounter.add(c, leaves[j]); j += 1 } }), 0);
  check("MerkleCounter.root" # suffix, alloc(func() { ignore MerkleCounter.root(c) }), rootBytes);

  let b = BitcoinMerkle.new(maxN, false);
  check("BitcoinMerkle.add" # suffix, alloc(func() { var j = 0; while (j < n) { BitcoinMerkle.add(b, leaves[j]); j += 1 } }), 0);
  check("BitcoinMerkle.root" # suffix, alloc(func() { ignore BitcoinMerkle.root(b) }), rootBytes);
};

// --- Trees over raw messages (fed through an embedded Digest) ---

for (n in ns.values()) {
  let suffix = " (n = " # n.toText() # ")";

  let s = MerkleStackState.new(maxN);
  check("MerkleStackState.add" # suffix, alloc(func() { var j = 0; while (j < n) { s.add(msgs[j]); j += 1 } }), 0);
  check("MerkleStackState.root" # suffix, alloc(func() { ignore s.root() }), readout);

  let c = MerkleCounterState.new(maxN);
  check("MerkleCounterState.add" # suffix, alloc(func() { var j = 0; while (j < n) { MerkleCounterState.add(c, msgs[j]); j += 1 } }), 0);
  check("MerkleCounterState.root" # suffix, alloc(func() { ignore MerkleCounterState.root(c) }), readout);

  let b = BitcoinTxMerkle.new(maxN, false);
  check("BitcoinTxMerkle.add" # suffix, alloc(func() { var j = 0; while (j < n) { BitcoinTxMerkle.add(b, msgs[j]); j += 1 } }), 0);
  check("BitcoinTxMerkle.root" # suffix, alloc(func() { ignore BitcoinTxMerkle.root(b) }), readout);
};

// Incremental use: a second root after more leaves again allocates only the root.
do {
  let c = MerkleCounter.new(maxN);
  for (j in Nat.range(0, 300)) MerkleCounter.add(c, leaves[j]);
  ignore MerkleCounter.root(c);
  check("MerkleCounter.add after root", alloc(func() { var j = 300; while (j < 700) { MerkleCounter.add(c, leaves[j]); j += 1 } }), 0);
  check("MerkleCounter.root again", alloc(func() { ignore MerkleCounter.root(c) }), readout);
};

// --- Coinbase witness (Example 7) ---

// Number of captured spine siblings for n leaves: one per level k with
// 2^(k+1) <= n, i.e. floor(log2 n).
func spineLevels(n : Nat) : Nat {
  var k = 0;
  var p = 2;
  while (p <= n) { k += 1; p *= 2 };
  k;
};
func isPow2(n : Nat) : Bool { var p = 1; while (p < n) p *= 2; p == n };
// Witness length: ceil(log2 n).
func ceilLog2(n : Nat) : Nat {
  var k = 0;
  var p = 1;
  while (p < n) { k += 1; p *= 2 };
  k;
};

for (n in ns.values()) {
  let suffix = " (n = " # n.toText() # ")";

  // Capture: one readout per spine level over the whole build, nothing per
  // leaf. In the Blob tree the level-0 sibling is the second leaf itself, kept
  // by reference; in the raw-transaction tree it exists only as hasher state.
  let b = BitcoinMerkle.new(maxN, true);
  check("BitcoinMerkle.add with witness" # suffix, alloc(func() { var j = 0; while (j < n) { BitcoinMerkle.add(b, leaves[j]); j += 1 } }), (if (n < 2) 0 else (spineLevels(n) - 1 : Nat)) * readout);
  let t = BitcoinTxMerkle.new(maxN, true);
  check("BitcoinTxMerkle.add with witness" # suffix, alloc(func() { var j = 0; while (j < n) { BitcoinTxMerkle.add(t, msgs[j]); j += 1 } }), spineLevels(n) * readout);

  // Extraction: the returned array plus the one remainder Blob (none for a
  // power of two, where the spine is the whole witness).
  let remainder = if (isPow2(n)) 0 else readout;
  // An empty witness (n = 1) is the static empty array: no allocation.
  let witnessArray = if (n == 1) 0 else arrayBytes(ceilLog2(n));
  // Plus the closure that builds the array: `VarArray.sliceToArray` for a
  // power of two (2 captured values, 48 bytes), otherwise `assemble`'s
  // `Array.tabulate` (3 captured values, 56 bytes). A closure takes a 24-byte
  // header, one word for the function and 8 bytes per captured value. The
  // point is that this is a constant: nothing depends on the tree size.
  let tabulate = if (n == 1) 0 else if (isPow2(n)) 48 else 56;
  var w : [Blob] = [];
  check("coinbaseWitness" # suffix, alloc(func() { w := b.coinbaseWitness() }), witnessArray + remainder + tabulate);
  var wTx : [Blob] = [];
  check("coinbaseWitnessTx" # suffix, alloc(func() { wTx := t.coinbaseWitnessTx() }), witnessArray + remainder + tabulate);

  // Verification: one Hasher and the folded root (verifyTx also its Digest).
  let root = BitcoinMerkle.root(b);
  let hasherBytes = alloc(func() { ignore Hasher.new() });
  let digestBytes = alloc(func() { ignore Sha256.new() });
  check("verifyTxid" # suffix, alloc(func() { assert BitcoinWitness.verifyTxid(leaves[0], w, root) }), hasherBytes + readout);
  check("verifyTx" # suffix, alloc(func() { assert BitcoinWitness.verifyTx(msgs[0], wTx, BitcoinTxMerkle.root(t)) }), digestBytes + hasherBytes + 2 * readout);
};

// --- N-fold hashing ---

// The rounds after the first are allocation-free: the cost does not depend on n.
do {
  let msg = bytes(100);
  let a2 = alloc(func() { ignore NFold.nfold(msg, 2) });
  check("nfold n = 1000 vs n = 2", alloc(func() { ignore NFold.nfold(msg, 1000) }), a2);
  let batch = Array.tabulate<Blob>(10, func(_) = bytes(50));
  let b2 = alloc(func() { ignore NFold.nfoldBatch(batch, 2) });
  check("nfoldBatch n = 1000 vs n = 2", alloc(func() { ignore NFold.nfoldBatch(batch, 1000) }), b2);
  // The batch reuses one Digest and one Hasher: one result Blob per message.
  let batch20 = Array.tabulate<Blob>(20, func(_) = bytes(50));
  check("nfoldBatch per message", alloc(func() { ignore NFold.nfoldBatch(batch20, 5) }) - b2, 10 * readout + arrayBytes(20) - arrayBytes(10));
};
