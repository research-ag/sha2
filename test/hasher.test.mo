import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Random "mo:core/Random";
import Sha256 "../src/Sha256";
import Hasher "../src/Hasher/Sha256";

// The single-shot `Hasher` must agree with the proven `Digest` path on every
// operation. Reference values all come from `Sha256` (fromBlob plus the
// write+sum path), which is independently tested against the SHA-256 vectors.
let rng = Random.seed(0xbeef);

func rnd32() : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));

// Reference SHA256(x ++ y) via the general Digest path.
func sha256Concat(x : Blob, y : Blob) : Blob {
  let d = Sha256.new();
  d.writeBlob(x);
  d.writeBlob(y);
  d.sum();
};

// Reuse one hasher throughout to also exercise the "reset-free reuse" property:
// every call overwrites the state from the IV, so no reset is ever needed.
let h = Hasher.new();

for (_ in Nat.range(0, 200)) {
  let a = rnd32();
  let b = rnd32();

  // hashBlob32(a) == SHA256(a)
  h.hashBlob32(a);
  assert (h.readSum() == Sha256.fromBlob(a));

  // hashState (self-fold) == double SHA256(a)
  h.hashBlob32(a);
  h.hashState(h);
  assert (h.readSum() == Sha256.fromBlob(Sha256.fromBlob(a)));

  // hashState from a different source == SHA256(src-state).
  // Build src = SHA256(b) in its own hasher, then hash that state into h.
  let src = Hasher.new();
  src.hashBlob32(b);
  h.hashState(src);
  assert (h.readSum() == Sha256.fromBlob(Sha256.fromBlob(b)));
  // src must be untouched (read-only source).
  assert (src.readSum() == Sha256.fromBlob(b));

  // combineBlob32(a, b) == SHA256(a ++ b)
  h.combineBlob32(a, b);
  assert (h.readSum() == sha256Concat(a, b));

  // combineState of two digest states == SHA256(SHA256(a) ++ SHA256(b)).
  // xa holds SHA256(a), yb holds SHA256(b).
  let xa = Hasher.new();
  xa.hashBlob32(a);
  let yb = Hasher.new();
  yb.hashBlob32(b);
  let nodeRef = sha256Concat(Sha256.fromBlob(a), Sha256.fromBlob(b));
  h.combineState(xa, yb);
  assert (h.readSum() == nodeRef);

  // Aliasing: combineState(self, self, other) climbs a Merkle level in place,
  // and must give the same node.
  let peak = Hasher.new();
  peak.hashBlob32(a); // peak = SHA256(a)
  let sib = Hasher.new();
  sib.hashBlob32(b); // sib = SHA256(b)
  peak.combineState(peak, sib); // peak := SHA256(peak ++ sib)
  assert (peak.readSum() == nodeRef);
};
