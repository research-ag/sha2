import Array "mo:core/Array";
import Random "mo:core/Random";
import Sha256 "../src/Sha256";
import Sha512 "../src/Sha512";

let rng = Random.seed(0x5077);

// Sha256.writeBlob fills a partial half-word and partial block before running
// whole blocks directly from the Blob. Split a message at odd and sub-block
// offsets so the second write starts mid-word and mid-block, and check the
// result against fromArray (an independent code path) regardless of the split.
for (algo in ([#sha256, #sha224] : [Sha256.Algorithm]).values()) {
  let total = 200;
  let data = Array.tabulate<Nat8>(total, func(_) = rng.nat8());
  let reference = Sha256.fromArray(algo, data);
  for (k in ([0, 1, 3, 5, 31, 32, 33, 64, 127] : [Nat]).values()) {
    let part1 = (Array.tabulate<Nat8>(k, func(i) = data[i])).toBlob();
    let part2 = (Array.tabulate<Nat8>(total - k, func(i) = data[k + i])).toBlob();
    let d = Sha256.new(algo);
    d.writeBlob(part1); // length k; odd k leaves the buffer mid-word
    d.writeBlob(part2); // starts mid-word for odd k
    assert (d.sum() == reference);
  };
};

// Sha512.writeBlob: same split check — odd/sub-block offsets exercise the
// guarded process_blocks path and the byte-alignment fixups.
for (algo in ([#sha512, #sha384, #sha512_224, #sha512_256] : [Sha512.Algorithm]).values()) {
  let total = 300;
  let data = Array.tabulate<Nat8>(total, func(_) = rng.nat8());
  let reference = Sha512.fromArray(algo, data);
  for (k in ([0, 1, 7, 8, 9, 64, 127, 128, 129, 200] : [Nat]).values()) {
    let part1 = (Array.tabulate<Nat8>(k, func(i) = data[i])).toBlob();
    let part2 = (Array.tabulate<Nat8>(total - k, func(i) = data[k + i])).toBlob();
    let d = Sha512.new(algo);
    d.writeBlob(part1);
    d.writeBlob(part2);
    assert (d.sum() == reference);
  };
};
