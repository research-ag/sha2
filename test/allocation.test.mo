// @testmode wasi

// Asserts the allocation behavior of the library operations:
//
// - `Hasher`: every function allocates nothing, except `readSum`, which
//   allocates exactly one readout.
// - Sha256/Sha224 `Digest`: `writeBlob`, `close`, `closeDouble` and `reset`
//   allocate nothing, for short and long messages; `readSum`, `sum` and
//   `sumDouble` exactly one readout. The other `write…` functions allocate
//   their closures (and `writeIter` its option values): a constant per call,
//   independent of the message length.
// - Sha512 family `Digest`: state and message words are `Nat64` values, which
//   are boxed when large, so writes and finalization allocate a data-dependent
//   amount. It is bounded per call: nothing is allocated per block.
//
// `Prim.rts_total_allocation()` is a monotonic counter of all bytes ever
// allocated, so its delta around a section is exactly what the section
// allocated. It is maintained only in compiled wasm, hence wasi test mode.
//
// Expected sizes are those of the 64-bit heap (moc 2.0.0): an object header
// is 3 words, so a 32-byte Blob takes 56 bytes and an array of n elements
// 24 + 8 * n bytes. On the 32-bit heap (moc 1.x with `--legacy-persistence`,
// run in CI) objects are smaller, so there the expected sizes are upper bounds
// (`<=`); an expected 0 stays exact on both heaps.

import Sha256 "../src/Sha256";
import Sha512 "../src/Sha512";
import Hasher "../src/Hasher/Sha256";
import Prim "mo:prim";

// Bytes allocated by `f`, measured after a warm-up run.
func alloc(f : () -> ()) : Nat {
  f();
  let before = Prim.rts_total_allocation();
  f();
  Prim.rts_total_allocation() - before;
};

// The word size of the heap: an array element takes one word.
let heap64 = alloc(func() { ignore Prim.Array_init<Nat>(2, 0) }) == alloc(func() { ignore Prim.Array_init<Nat>(1, 0) }) + 8;

func check(name : Text, actual : Nat, expected : Nat) {
  if (if heap64 actual != expected else actual > expected) {
    Prim.debugPrint(name # ": allocated " # debug_show actual # " bytes, expected " # (if heap64 "" else "at most ") # debug_show expected);
    assert false;
  };
};

// An upper bound on both heaps.
func checkAtMost(name : Text, actual : Nat, bound : Nat) {
  if (actual > bound) {
    Prim.debugPrint(name # ": allocated " # debug_show actual # " bytes, expected at most " # debug_show bound);
    assert false;
  };
};

func arrayBytes(n : Nat) : Nat = 24 + 8 * n;
func blobBytes(n : Nat) : Nat = 24 + (n + 7) / 8 * 8; // the payload is padded to whole words
// A hash readout builds the bytes as a `[Nat8]` first and then the Blob.
func readout(n : Nat) : Nat = arrayBytes(n) + blobBytes(n);

// --- Harness validation ---

check("empty function", alloc(func() {}), 0);
check("array of 5", alloc(func() { ignore Prim.Array_init<Nat>(5, 0) }), arrayBytes(5));
assert alloc(func() { ignore Prim.Array_init<Nat>(5, 0) }) > 0;

// --- Test data ---

func bytes(n : Nat) : Blob = Prim.arrayToBlob(Prim.Array_tabulate<Nat8>(n, func(i) = Prim.natToNat8((i * 7 + 3) % 256)));
let b32 = bytes(32);
// A short message (a partial block plus one full block for either block
// size) and a long one (hundreds of blocks).
let short = bytes(200);
let long = bytes(64_000);
let shortArray = Prim.blobToArray(short);
let longArray = Prim.blobToArray(long);
func toVar(a : [Nat8]) : [var Nat8] {
  let v = Prim.Array_init<Nat8>(a.size(), 0);
  var i = 0;
  while (i < a.size()) { v[i] := a[i]; i += 1 };
  v;
};
let shortMut = toVar(shortArray);
let longMut = toVar(longArray);

// --- Hasher ---

do {
  let h = Hasher.new();
  let h2 = Hasher.new();
  h2.hashBlob32(b32);
  check("Hasher.hashBlob32", alloc(func() = h.hashBlob32(b32)), 0);
  check("Hasher.hashState", alloc(func() = h.hashState(h2)), 0);
  check("Hasher.hashState in place", alloc(func() = h.hashState(h)), 0);
  check("Hasher.combineBlob32", alloc(func() = h.combineBlob32(b32, b32)), 0);
  check("Hasher.combineState", alloc(func() = h.combineState(h, h2)), 0);
  check("Hasher.combineStateBlob32", alloc(func() = h.combineStateBlob32(h, b32)), 0);
  check("Hasher.combineBlob32State", alloc(func() = h.combineBlob32State(b32, h)), 0);
  check("Hasher.loadBlob32", alloc(func() = h.loadBlob32(b32)), 0);
  check("Hasher.loadState", alloc(func() = h.loadState(h2)), 0);
  check("Hasher.readSum", alloc(func() { ignore h.readSum() }), readout(32));
};

// --- Sha256 / Sha224 ---

for (algo in ([#sha256, #sha224] : [Sha256.Algorithm]).values()) {
  let n = debug_show algo # " ";
  let len = if (algo == #sha256) 32 else 28;
  let d = Sha256.new(algo);

  check(n # "writeBlob short", alloc(func() = d.writeBlob(short)), 0);
  check(n # "writeBlob long", alloc(func() = d.writeBlob(long)), 0);
  check(n # "reset", alloc(func() = d.reset()), 0);
  check(n # "close", alloc(func() { d.reset(); d.writeBlob(short); d.close() }), 0);
  check(n # "readSum", alloc(func() { ignore d.readSum() }), readout(len));
  check(n # "sum", alloc(func() { d.reset(); d.writeBlob(short); ignore d.sum() }), readout(len));
  if (algo == #sha256) {
    check(n # "closeDouble", alloc(func() { d.reset(); d.writeBlob(short); d.closeDouble() }), 0);
    check(n # "sumDouble", alloc(func() { d.reset(); d.writeBlob(short); ignore d.sumDouble() }), readout(32));
  };

  // The closure-based writes: a constant per call.
  d.reset();
  let a = alloc(func() = d.writeArray(shortArray));
  check(n # "writeArray long vs short", alloc(func() = d.writeArray(longArray)), a);
  let v = alloc(func() = d.writeVarArray(shortMut));
  check(n # "writeVarArray long vs short", alloc(func() = d.writeVarArray(longMut)), v);
  let shortAt = func(i : Nat) : Nat8 = shortArray[i];
  let longAt = func(i : Nat) : Nat8 = longArray[i];
  let c = alloc(func() = d.writeAccessor(shortAt, 0, short.size()));
  check(n # "writeAccessor long vs short", alloc(func() = d.writeAccessor(longAt, 0, long.size())), c);
  var pos = 0;
  let shortNext = func() : Nat8 {
    let b = shortArray[pos % short.size()];
    pos += 1;
    b;
  };
  let longNext = func() : Nat8 {
    let b = longArray[pos % long.size()];
    pos += 1;
    b;
  };
  let r = alloc(func() = d.writeReader(shortNext, short.size()));
  check(n # "writeReader long vs short", alloc(func() = d.writeReader(longNext, long.size())), r);
};

// --- Sha512 family ---

// At most one box per message word, state word and partial word, plus the
// closures of a write: about 1 KiB on the 64-bit heap. A long message must
// stay within the same bound, so nothing is allocated per block.
let sha512Bound = 2048;
for (algo in ([#sha512, #sha384, #sha512_256, #sha512_224] : [Sha512.Algorithm]).values()) {
  let n = debug_show algo # " ";
  let d = Sha512.new(algo);
  check(n # "reset", alloc(func() = d.reset()), 0);
  checkAtMost(n # "writeBlob short", alloc(func() = d.writeBlob(short)), sha512Bound);
  checkAtMost(n # "writeBlob long", alloc(func() = d.writeBlob(long)), sha512Bound);
  checkAtMost(n # "writeArray long", alloc(func() = d.writeArray(longArray)), sha512Bound);
  checkAtMost(n # "writeVarArray long", alloc(func() = d.writeVarArray(longMut)), sha512Bound);
  checkAtMost(n # "close", alloc(func() { d.reset(); d.writeBlob(short); d.close() }), 2 * sha512Bound);
  checkAtMost(n # "sum", alloc(func() { d.reset(); d.writeBlob(short); ignore d.sum() }), 2 * sha512Bound);
};
