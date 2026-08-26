/// SHA-512 round constants (K00-K79): the first 64 bits of the fractional parts of the cube roots of the first 80 primes.

module {
  /// SHA-512 round constant K00 (#1 of the first 80 primes).
  public let K00 : Nat64 = 0x428a2f98d728ae22;
  /// SHA-512 round constant K01 (#2 of the first 80 primes).
  public let K01 : Nat64 = 0x7137449123ef65cd;
  /// SHA-512 round constant K02 (#3 of the first 80 primes).
  public let K02 : Nat64 = 0xb5c0fbcfec4d3b2f;
  /// SHA-512 round constant K03 (#4 of the first 80 primes).
  public let K03 : Nat64 = 0xe9b5dba58189dbbc;
  /// SHA-512 round constant K04 (#5 of the first 80 primes).
  public let K04 : Nat64 = 0x3956c25bf348b538;
  /// SHA-512 round constant K05 (#6 of the first 80 primes).
  public let K05 : Nat64 = 0x59f111f1b605d019;
  /// SHA-512 round constant K06 (#7 of the first 80 primes).
  public let K06 : Nat64 = 0x923f82a4af194f9b;
  /// SHA-512 round constant K07 (#8 of the first 80 primes).
  public let K07 : Nat64 = 0xab1c5ed5da6d8118;
  /// SHA-512 round constant K08 (#9 of the first 80 primes).
  public let K08 : Nat64 = 0xd807aa98a3030242;
  /// SHA-512 round constant K09 (#10 of the first 80 primes).
  public let K09 : Nat64 = 0x12835b0145706fbe;
  /// SHA-512 round constant K10 (#11 of the first 80 primes).
  public let K10 : Nat64 = 0x243185be4ee4b28c;
  /// SHA-512 round constant K11 (#12 of the first 80 primes).
  public let K11 : Nat64 = 0x550c7dc3d5ffb4e2;
  /// SHA-512 round constant K12 (#13 of the first 80 primes).
  public let K12 : Nat64 = 0x72be5d74f27b896f;
  /// SHA-512 round constant K13 (#14 of the first 80 primes).
  public let K13 : Nat64 = 0x80deb1fe3b1696b1;
  /// SHA-512 round constant K14 (#15 of the first 80 primes).
  public let K14 : Nat64 = 0x9bdc06a725c71235;
  /// SHA-512 round constant K15 (#16 of the first 80 primes).
  public let K15 : Nat64 = 0xc19bf174cf692694;
  /// SHA-512 round constant K16 (#17 of the first 80 primes).
  public let K16 : Nat64 = 0xe49b69c19ef14ad2;
  /// SHA-512 round constant K17 (#18 of the first 80 primes).
  public let K17 : Nat64 = 0xefbe4786384f25e3;
  /// SHA-512 round constant K18 (#19 of the first 80 primes).
  public let K18 : Nat64 = 0x0fc19dc68b8cd5b5;
  /// SHA-512 round constant K19 (#20 of the first 80 primes).
  public let K19 : Nat64 = 0x240ca1cc77ac9c65;
  /// SHA-512 round constant K20 (#21 of the first 80 primes).
  public let K20 : Nat64 = 0x2de92c6f592b0275;
  /// SHA-512 round constant K21 (#22 of the first 80 primes).
  public let K21 : Nat64 = 0x4a7484aa6ea6e483;
  /// SHA-512 round constant K22 (#23 of the first 80 primes).
  public let K22 : Nat64 = 0x5cb0a9dcbd41fbd4;
  /// SHA-512 round constant K23 (#24 of the first 80 primes).
  public let K23 : Nat64 = 0x76f988da831153b5;
  /// SHA-512 round constant K24 (#25 of the first 80 primes).
  public let K24 : Nat64 = 0x983e5152ee66dfab;
  /// SHA-512 round constant K25 (#26 of the first 80 primes).
  public let K25 : Nat64 = 0xa831c66d2db43210;
  /// SHA-512 round constant K26 (#27 of the first 80 primes).
  public let K26 : Nat64 = 0xb00327c898fb213f;
  /// SHA-512 round constant K27 (#28 of the first 80 primes).
  public let K27 : Nat64 = 0xbf597fc7beef0ee4;
  /// SHA-512 round constant K28 (#29 of the first 80 primes).
  public let K28 : Nat64 = 0xc6e00bf33da88fc2;
  /// SHA-512 round constant K29 (#30 of the first 80 primes).
  public let K29 : Nat64 = 0xd5a79147930aa725;
  /// SHA-512 round constant K30 (#31 of the first 80 primes).
  public let K30 : Nat64 = 0x06ca6351e003826f;
  /// SHA-512 round constant K31 (#32 of the first 80 primes).
  public let K31 : Nat64 = 0x142929670a0e6e70;
  /// SHA-512 round constant K32 (#33 of the first 80 primes).
  public let K32 : Nat64 = 0x27b70a8546d22ffc;
  /// SHA-512 round constant K33 (#34 of the first 80 primes).
  public let K33 : Nat64 = 0x2e1b21385c26c926;
  /// SHA-512 round constant K34 (#35 of the first 80 primes).
  public let K34 : Nat64 = 0x4d2c6dfc5ac42aed;
  /// SHA-512 round constant K35 (#36 of the first 80 primes).
  public let K35 : Nat64 = 0x53380d139d95b3df;
  /// SHA-512 round constant K36 (#37 of the first 80 primes).
  public let K36 : Nat64 = 0x650a73548baf63de;
  /// SHA-512 round constant K37 (#38 of the first 80 primes).
  public let K37 : Nat64 = 0x766a0abb3c77b2a8;
  /// SHA-512 round constant K38 (#39 of the first 80 primes).
  public let K38 : Nat64 = 0x81c2c92e47edaee6;
  /// SHA-512 round constant K39 (#40 of the first 80 primes).
  public let K39 : Nat64 = 0x92722c851482353b;
  /// SHA-512 round constant K40 (#41 of the first 80 primes).
  public let K40 : Nat64 = 0xa2bfe8a14cf10364;
  /// SHA-512 round constant K41 (#42 of the first 80 primes).
  public let K41 : Nat64 = 0xa81a664bbc423001;
  /// SHA-512 round constant K42 (#43 of the first 80 primes).
  public let K42 : Nat64 = 0xc24b8b70d0f89791;
  /// SHA-512 round constant K43 (#44 of the first 80 primes).
  public let K43 : Nat64 = 0xc76c51a30654be30;
  /// SHA-512 round constant K44 (#45 of the first 80 primes).
  public let K44 : Nat64 = 0xd192e819d6ef5218;
  /// SHA-512 round constant K45 (#46 of the first 80 primes).
  public let K45 : Nat64 = 0xd69906245565a910;
  /// SHA-512 round constant K46 (#47 of the first 80 primes).
  public let K46 : Nat64 = 0xf40e35855771202a;
  /// SHA-512 round constant K47 (#48 of the first 80 primes).
  public let K47 : Nat64 = 0x106aa07032bbd1b8;
  /// SHA-512 round constant K48 (#49 of the first 80 primes).
  public let K48 : Nat64 = 0x19a4c116b8d2d0c8;
  /// SHA-512 round constant K49 (#50 of the first 80 primes).
  public let K49 : Nat64 = 0x1e376c085141ab53;
  /// SHA-512 round constant K50 (#51 of the first 80 primes).
  public let K50 : Nat64 = 0x2748774cdf8eeb99;
  /// SHA-512 round constant K51 (#52 of the first 80 primes).
  public let K51 : Nat64 = 0x34b0bcb5e19b48a8;
  /// SHA-512 round constant K52 (#53 of the first 80 primes).
  public let K52 : Nat64 = 0x391c0cb3c5c95a63;
  /// SHA-512 round constant K53 (#54 of the first 80 primes).
  public let K53 : Nat64 = 0x4ed8aa4ae3418acb;
  /// SHA-512 round constant K54 (#55 of the first 80 primes).
  public let K54 : Nat64 = 0x5b9cca4f7763e373;
  /// SHA-512 round constant K55 (#56 of the first 80 primes).
  public let K55 : Nat64 = 0x682e6ff3d6b2b8a3;
  /// SHA-512 round constant K56 (#57 of the first 80 primes).
  public let K56 : Nat64 = 0x748f82ee5defb2fc;
  /// SHA-512 round constant K57 (#58 of the first 80 primes).
  public let K57 : Nat64 = 0x78a5636f43172f60;
  /// SHA-512 round constant K58 (#59 of the first 80 primes).
  public let K58 : Nat64 = 0x84c87814a1f0ab72;
  /// SHA-512 round constant K59 (#60 of the first 80 primes).
  public let K59 : Nat64 = 0x8cc702081a6439ec;
  /// SHA-512 round constant K60 (#61 of the first 80 primes).
  public let K60 : Nat64 = 0x90befffa23631e28;
  /// SHA-512 round constant K61 (#62 of the first 80 primes).
  public let K61 : Nat64 = 0xa4506cebde82bde9;
  /// SHA-512 round constant K62 (#63 of the first 80 primes).
  public let K62 : Nat64 = 0xbef9a3f7b2c67915;
  /// SHA-512 round constant K63 (#64 of the first 80 primes).
  public let K63 : Nat64 = 0xc67178f2e372532b;
  /// SHA-512 round constant K64 (#65 of the first 80 primes).
  public let K64 : Nat64 = 0xca273eceea26619c;
  /// SHA-512 round constant K65 (#66 of the first 80 primes).
  public let K65 : Nat64 = 0xd186b8c721c0c207;
  /// SHA-512 round constant K66 (#67 of the first 80 primes).
  public let K66 : Nat64 = 0xeada7dd6cde0eb1e;
  /// SHA-512 round constant K67 (#68 of the first 80 primes).
  public let K67 : Nat64 = 0xf57d4f7fee6ed178;
  /// SHA-512 round constant K68 (#69 of the first 80 primes).
  public let K68 : Nat64 = 0x06f067aa72176fba;
  /// SHA-512 round constant K69 (#70 of the first 80 primes).
  public let K69 : Nat64 = 0x0a637dc5a2c898a6;
  /// SHA-512 round constant K70 (#71 of the first 80 primes).
  public let K70 : Nat64 = 0x113f9804bef90dae;
  /// SHA-512 round constant K71 (#72 of the first 80 primes).
  public let K71 : Nat64 = 0x1b710b35131c471b;
  /// SHA-512 round constant K72 (#73 of the first 80 primes).
  public let K72 : Nat64 = 0x28db77f523047d84;
  /// SHA-512 round constant K73 (#74 of the first 80 primes).
  public let K73 : Nat64 = 0x32caab7b40c72493;
  /// SHA-512 round constant K74 (#75 of the first 80 primes).
  public let K74 : Nat64 = 0x3c9ebe0a15c9bebc;
  /// SHA-512 round constant K75 (#76 of the first 80 primes).
  public let K75 : Nat64 = 0x431d67c49c100d4c;
  /// SHA-512 round constant K76 (#77 of the first 80 primes).
  public let K76 : Nat64 = 0x4cc5d4becb3e42b6;
  /// SHA-512 round constant K77 (#78 of the first 80 primes).
  public let K77 : Nat64 = 0x597f299cfc657e2a;
  /// SHA-512 round constant K78 (#79 of the first 80 primes).
  public let K78 : Nat64 = 0x5fcb6fab3ad6faec;
  /// SHA-512 round constant K79 (#80 of the first 80 primes).
  public let K79 : Nat64 = 0x6c44198c4a475817;
};
