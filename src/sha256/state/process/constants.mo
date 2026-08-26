/// SHA-256 round constants (K00-K63): the first 32 bits of the fractional parts of the cube roots of the first 64 primes.

module {
  /// SHA-256 round constant K00 (#1 of the first 64 primes).
  public let K00 : Nat32 = 0x428a2f98;
  /// SHA-256 round constant K01 (#2 of the first 64 primes).
  public let K01 : Nat32 = 0x71374491;
  /// SHA-256 round constant K02 (#3 of the first 64 primes).
  public let K02 : Nat32 = 0xb5c0fbcf;
  /// SHA-256 round constant K03 (#4 of the first 64 primes).
  public let K03 : Nat32 = 0xe9b5dba5;
  /// SHA-256 round constant K04 (#5 of the first 64 primes).
  public let K04 : Nat32 = 0x3956c25b;
  /// SHA-256 round constant K05 (#6 of the first 64 primes).
  public let K05 : Nat32 = 0x59f111f1;
  /// SHA-256 round constant K06 (#7 of the first 64 primes).
  public let K06 : Nat32 = 0x923f82a4;
  /// SHA-256 round constant K07 (#8 of the first 64 primes).
  public let K07 : Nat32 = 0xab1c5ed5;
  /// SHA-256 round constant K08 (#9 of the first 64 primes).
  public let K08 : Nat32 = 0xd807aa98;
  /// SHA-256 round constant K09 (#10 of the first 64 primes).
  public let K09 : Nat32 = 0x12835b01;
  /// SHA-256 round constant K10 (#11 of the first 64 primes).
  public let K10 : Nat32 = 0x243185be;
  /// SHA-256 round constant K11 (#12 of the first 64 primes).
  public let K11 : Nat32 = 0x550c7dc3;
  /// SHA-256 round constant K12 (#13 of the first 64 primes).
  public let K12 : Nat32 = 0x72be5d74;
  /// SHA-256 round constant K13 (#14 of the first 64 primes).
  public let K13 : Nat32 = 0x80deb1fe;
  /// SHA-256 round constant K14 (#15 of the first 64 primes).
  public let K14 : Nat32 = 0x9bdc06a7;
  /// SHA-256 round constant K15 (#16 of the first 64 primes).
  public let K15 : Nat32 = 0xc19bf174;
  /// SHA-256 round constant K16 (#17 of the first 64 primes).
  public let K16 : Nat32 = 0xe49b69c1;
  /// SHA-256 round constant K17 (#18 of the first 64 primes).
  public let K17 : Nat32 = 0xefbe4786;
  /// SHA-256 round constant K18 (#19 of the first 64 primes).
  public let K18 : Nat32 = 0x0fc19dc6;
  /// SHA-256 round constant K19 (#20 of the first 64 primes).
  public let K19 : Nat32 = 0x240ca1cc;
  /// SHA-256 round constant K20 (#21 of the first 64 primes).
  public let K20 : Nat32 = 0x2de92c6f;
  /// SHA-256 round constant K21 (#22 of the first 64 primes).
  public let K21 : Nat32 = 0x4a7484aa;
  /// SHA-256 round constant K22 (#23 of the first 64 primes).
  public let K22 : Nat32 = 0x5cb0a9dc;
  /// SHA-256 round constant K23 (#24 of the first 64 primes).
  public let K23 : Nat32 = 0x76f988da;
  /// SHA-256 round constant K24 (#25 of the first 64 primes).
  public let K24 : Nat32 = 0x983e5152;
  /// SHA-256 round constant K25 (#26 of the first 64 primes).
  public let K25 : Nat32 = 0xa831c66d;
  /// SHA-256 round constant K26 (#27 of the first 64 primes).
  public let K26 : Nat32 = 0xb00327c8;
  /// SHA-256 round constant K27 (#28 of the first 64 primes).
  public let K27 : Nat32 = 0xbf597fc7;
  /// SHA-256 round constant K28 (#29 of the first 64 primes).
  public let K28 : Nat32 = 0xc6e00bf3;
  /// SHA-256 round constant K29 (#30 of the first 64 primes).
  public let K29 : Nat32 = 0xd5a79147;
  /// SHA-256 round constant K30 (#31 of the first 64 primes).
  public let K30 : Nat32 = 0x06ca6351;
  /// SHA-256 round constant K31 (#32 of the first 64 primes).
  public let K31 : Nat32 = 0x14292967;
  /// SHA-256 round constant K32 (#33 of the first 64 primes).
  public let K32 : Nat32 = 0x27b70a85;
  /// SHA-256 round constant K33 (#34 of the first 64 primes).
  public let K33 : Nat32 = 0x2e1b2138;
  /// SHA-256 round constant K34 (#35 of the first 64 primes).
  public let K34 : Nat32 = 0x4d2c6dfc;
  /// SHA-256 round constant K35 (#36 of the first 64 primes).
  public let K35 : Nat32 = 0x53380d13;
  /// SHA-256 round constant K36 (#37 of the first 64 primes).
  public let K36 : Nat32 = 0x650a7354;
  /// SHA-256 round constant K37 (#38 of the first 64 primes).
  public let K37 : Nat32 = 0x766a0abb;
  /// SHA-256 round constant K38 (#39 of the first 64 primes).
  public let K38 : Nat32 = 0x81c2c92e;
  /// SHA-256 round constant K39 (#40 of the first 64 primes).
  public let K39 : Nat32 = 0x92722c85;
  /// SHA-256 round constant K40 (#41 of the first 64 primes).
  public let K40 : Nat32 = 0xa2bfe8a1;
  /// SHA-256 round constant K41 (#42 of the first 64 primes).
  public let K41 : Nat32 = 0xa81a664b;
  /// SHA-256 round constant K42 (#43 of the first 64 primes).
  public let K42 : Nat32 = 0xc24b8b70;
  /// SHA-256 round constant K43 (#44 of the first 64 primes).
  public let K43 : Nat32 = 0xc76c51a3;
  /// SHA-256 round constant K44 (#45 of the first 64 primes).
  public let K44 : Nat32 = 0xd192e819;
  /// SHA-256 round constant K45 (#46 of the first 64 primes).
  public let K45 : Nat32 = 0xd6990624;
  /// SHA-256 round constant K46 (#47 of the first 64 primes).
  public let K46 : Nat32 = 0xf40e3585;
  /// SHA-256 round constant K47 (#48 of the first 64 primes).
  public let K47 : Nat32 = 0x106aa070;
  /// SHA-256 round constant K48 (#49 of the first 64 primes).
  public let K48 : Nat32 = 0x19a4c116;
  /// SHA-256 round constant K49 (#50 of the first 64 primes).
  public let K49 : Nat32 = 0x1e376c08;
  /// SHA-256 round constant K50 (#51 of the first 64 primes).
  public let K50 : Nat32 = 0x2748774c;
  /// SHA-256 round constant K51 (#52 of the first 64 primes).
  public let K51 : Nat32 = 0x34b0bcb5;
  /// SHA-256 round constant K52 (#53 of the first 64 primes).
  public let K52 : Nat32 = 0x391c0cb3;
  /// SHA-256 round constant K53 (#54 of the first 64 primes).
  public let K53 : Nat32 = 0x4ed8aa4a;
  /// SHA-256 round constant K54 (#55 of the first 64 primes).
  public let K54 : Nat32 = 0x5b9cca4f;
  /// SHA-256 round constant K55 (#56 of the first 64 primes).
  public let K55 : Nat32 = 0x682e6ff3;
  /// SHA-256 round constant K56 (#57 of the first 64 primes).
  public let K56 : Nat32 = 0x748f82ee;
  /// SHA-256 round constant K57 (#58 of the first 64 primes).
  public let K57 : Nat32 = 0x78a5636f;
  /// SHA-256 round constant K58 (#59 of the first 64 primes).
  public let K58 : Nat32 = 0x84c87814;
  /// SHA-256 round constant K59 (#60 of the first 64 primes).
  public let K59 : Nat32 = 0x8cc70208;
  /// SHA-256 round constant K60 (#61 of the first 64 primes).
  public let K60 : Nat32 = 0x90befffa;
  /// SHA-256 round constant K61 (#62 of the first 64 primes).
  public let K61 : Nat32 = 0xa4506ceb;
  /// SHA-256 round constant K62 (#63 of the first 64 primes).
  public let K62 : Nat32 = 0xbef9a3f7;
  /// SHA-256 round constant K63 (#64 of the first 64 primes).
  public let K63 : Nat32 = 0xc67178f2;
};
