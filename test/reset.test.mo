import Sha256 "../src/Sha256";
import Sha512 "../src/Sha512";

// Regression: reset() must re-open a finalized (closed) digest so it can be
// reused for a new message. Sha512.reset() previously forgot to clear the
// `closed` flag, so the second writeBlob below trapped.
for (algo in ([#sha256, #sha224] : [Sha256.Algorithm]).values()) {
  let d = Sha256.new(algo);
  d.writeBlob("first");
  let h1 = d.sum(); // closes the digest
  d.reset();
  d.writeBlob("first");
  assert (d.sum() == h1); // same input after reset -> same hash
};

for (algo in ([#sha512, #sha384, #sha512_224, #sha512_256] : [Sha512.Algorithm]).values()) {
  let d = Sha512.new(algo);
  d.writeBlob("first");
  let h1 = d.sum(); // closes the digest
  d.reset();
  d.writeBlob("first");
  assert (d.sum() == h1); // same input after reset -> same hash
};
