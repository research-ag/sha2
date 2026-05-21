import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Random "mo:core/Random";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Sha256 "../src/Sha256";
import Sha512 "../src/Sha512";

// Generate 256 random bytes
let rng = Random.seed(0xdeadbeef);
let data = Array.tabulate<Nat8>(256, func(i) = rng.nat8());

// Define accessor function
func accessor(i : Nat) : Nat8 = data[i];

// Get reference hash by processing all at once
let reference256 = Sha256.fromArray(data);
let reference512 = Sha512.fromArray(data);

// Test fromAccessor
assert (Sha256.fromAccessor(accessor, 0, 256) == reference256);
assert (Sha512.fromAccessor(accessor, 0, 256) == reference512);

// SHA256 tests

// Test 1 chunk of 256 bytes
do {
  let d = Sha256.new();
  d.writeAccessor(accessor, 0, 256);
  assert (d.sum() == reference256);
};

// Test 2 chunks of 128 bytes
do {
  let d = Sha256.new();
  d.writeAccessor(accessor, 0, 128);
  d.writeAccessor(accessor, 128, 128);
  assert (d.sum() == reference256);
};

// Test 4 chunks of 64 bytes
do {
  let d = Sha256.new();
  for (i in Nat.range(0, 4)) {
    d.writeAccessor(accessor, i * 64, 64);
  };
  assert (d.sum() == reference256);
};

// Test 32-byte chunks
do {
  let d = Sha256.new();
  for (i in Nat.range(0, 8)) {
    d.writeAccessor(accessor, i * 32, 32);
  };
  assert (d.sum() == reference256);
};

// Test 16-byte chunks
do {
  let d = Sha256.new();
  for (i in Nat.range(0, 16)) {
    d.writeAccessor(accessor, i * 16, 16);
  };
  assert (d.sum() == reference256);
};

// Test 8-byte chunks
do {
  let d = Sha256.new();
  for (i in Nat.range(0, 32)) {
    d.writeAccessor(accessor, i * 8, 8);
  };
  assert (d.sum() == reference256);
};

// Test 4-byte chunks
do {
  let d = Sha256.new();
  for (i in Nat.range(0, 64)) {
    d.writeAccessor(accessor, i * 4, 4);
  };
  assert (d.sum() == reference256);
};

// Test 2-byte chunks
do {
  let d = Sha256.new();
  for (i in Nat.range(0, 128)) {
    d.writeAccessor(accessor, i * 2, 2);
  };
  assert (d.sum() == reference256);
};

// Test 1-byte chunks
do {
  let d = Sha256.new();
  for (i in Nat.range(0, 256)) {
    d.writeAccessor(accessor, i, 1);
  };
  assert (d.sum() == reference256);
};

// SHA512 tests
// Test 1 chunk of 512 bytes

do {
  let d = Sha512.new();
  d.writeAccessor(accessor, 0, 256);
  assert (d.sum() == reference512);
};

// Test 2 chunks of 128 bytes
do {
  let d = Sha512.new();
  d.writeAccessor(accessor, 0, 128);
  d.writeAccessor(accessor, 128, 128);
  assert (d.sum() == reference512);
};

// Test 4 chunks of 64 bytes
do {
  let d = Sha512.new();
  for (i in Nat.range(0, 4)) {
    d.writeAccessor(accessor, i * 64, 64);
  };
  assert (d.sum() == reference512);
};

// Test 32-byte chunks
do {
  let d = Sha512.new();
  for (i in Nat.range(0, 8)) {
    d.writeAccessor(accessor, i * 32, 32);
  };
  assert (d.sum() == reference512);
};

// Test 16-byte chunks
do {
  let d = Sha512.new();
  for (i in Nat.range(0, 16)) {
    d.writeAccessor(accessor, i * 16, 16);
  };
  assert (d.sum() == reference512);
};

// Test 8-byte chunks
do {
  let d = Sha512.new();
  for (i in Nat.range(0, 32)) {
    d.writeAccessor(accessor, i * 8, 8);
  };
  assert (d.sum() == reference512);
};

// Test 4-byte chunks
do {
  let d = Sha512.new();
  for (i in Nat.range(0, 64)) {
    d.writeAccessor(accessor, i * 4, 4);
  };
  assert (d.sum() == reference512);
};

// Test 2-byte chunks
do {
  let d = Sha512.new();
  for (i in Nat.range(0, 128)) {
    d.writeAccessor(accessor, i * 2, 2);
  };
  assert (d.sum() == reference512);
};

// Test 1-byte chunks
do {
  let d = Sha512.new();
  for (i in Nat.range(0, 256)) {
    d.writeAccessor(accessor, i, 1);
  };
  assert (d.sum() == reference512);
};
