module {
  public let ivs : [[Nat64]] = [
    [
      // 512-224
      0x8c3d37c819544da2,
      0x73e1996689dcd4d6,
      0x1dfab7ae32ff9c82,
      0x679dd514582f9fcf,
      0x0f6d2b697bd44da8,
      0x77e36f7304c48942,
      0x3f9d85a86a1d36c8,
      0x1112e6ad91d692a1,
    ],
    [
      // 512-256
      0x22312194fc2bf72c,
      0x9f555fa3c84c64c2,
      0x2393b86b6f53b151,
      0x963877195940eabd,
      0x96283ee2a88effe3,
      0xbe5e1e2553863992,
      0x2b0199fc2c85b8aa,
      0x0eb72ddc81c52ca2,
    ],
    [
      // 384
      0xcbbb9d5dc1059ed8,
      0x629a292a367cd507,
      0x9159015a3070dd17,
      0x152fecd8f70e5939,
      0x67332667ffc00b31,
      0x8eb44a8768581511,
      0xdb0c2e0d64f98fa7,
      0x47b5481dbefa4fa4,
    ],
    [
      // 512
      0x6a09e667f3bcc908,
      0xbb67ae8584caa73b,
      0x3c6ef372fe94f82b,
      0xa54ff53a5f1d36f1,
      0x510e527fade682d1,
      0x9b05688c2b3e6c1f,
      0x1f83d9abfb41bd6b,
      0x5be0cd19137e2179,
    ],
  ];

  public let K00 : Nat64 = 0x428a2f98d728ae22;
  public let K01 : Nat64 = 0x7137449123ef65cd;
  public let K02 : Nat64 = 0xb5c0fbcfec4d3b2f;
  public let K03 : Nat64 = 0xe9b5dba58189dbbc;
  public let K04 : Nat64 = 0x3956c25bf348b538;
  public let K05 : Nat64 = 0x59f111f1b605d019;
  public let K06 : Nat64 = 0x923f82a4af194f9b;
  public let K07 : Nat64 = 0xab1c5ed5da6d8118;
  public let K08 : Nat64 = 0xd807aa98a3030242;
  public let K09 : Nat64 = 0x12835b0145706fbe;
  public let K10 : Nat64 = 0x243185be4ee4b28c;
  public let K11 : Nat64 = 0x550c7dc3d5ffb4e2;
  public let K12 : Nat64 = 0x72be5d74f27b896f;
  public let K13 : Nat64 = 0x80deb1fe3b1696b1;
  public let K14 : Nat64 = 0x9bdc06a725c71235;
  public let K15 : Nat64 = 0xc19bf174cf692694;
  public let K16 : Nat64 = 0xe49b69c19ef14ad2;
  public let K17 : Nat64 = 0xefbe4786384f25e3;
  public let K18 : Nat64 = 0x0fc19dc68b8cd5b5;
  public let K19 : Nat64 = 0x240ca1cc77ac9c65;
  public let K20 : Nat64 = 0x2de92c6f592b0275;
  public let K21 : Nat64 = 0x4a7484aa6ea6e483;
  public let K22 : Nat64 = 0x5cb0a9dcbd41fbd4;
  public let K23 : Nat64 = 0x76f988da831153b5;
  public let K24 : Nat64 = 0x983e5152ee66dfab;
  public let K25 : Nat64 = 0xa831c66d2db43210;
  public let K26 : Nat64 = 0xb00327c898fb213f;
  public let K27 : Nat64 = 0xbf597fc7beef0ee4;
  public let K28 : Nat64 = 0xc6e00bf33da88fc2;
  public let K29 : Nat64 = 0xd5a79147930aa725;
  public let K30 : Nat64 = 0x06ca6351e003826f;
  public let K31 : Nat64 = 0x142929670a0e6e70;
  public let K32 : Nat64 = 0x27b70a8546d22ffc;
  public let K33 : Nat64 = 0x2e1b21385c26c926;
  public let K34 : Nat64 = 0x4d2c6dfc5ac42aed;
  public let K35 : Nat64 = 0x53380d139d95b3df;
  public let K36 : Nat64 = 0x650a73548baf63de;
  public let K37 : Nat64 = 0x766a0abb3c77b2a8;
  public let K38 : Nat64 = 0x81c2c92e47edaee6;
  public let K39 : Nat64 = 0x92722c851482353b;
  public let K40 : Nat64 = 0xa2bfe8a14cf10364;
  public let K41 : Nat64 = 0xa81a664bbc423001;
  public let K42 : Nat64 = 0xc24b8b70d0f89791;
  public let K43 : Nat64 = 0xc76c51a30654be30;
  public let K44 : Nat64 = 0xd192e819d6ef5218;
  public let K45 : Nat64 = 0xd69906245565a910;
  public let K46 : Nat64 = 0xf40e35855771202a;
  public let K47 : Nat64 = 0x106aa07032bbd1b8;
  public let K48 : Nat64 = 0x19a4c116b8d2d0c8;
  public let K49 : Nat64 = 0x1e376c085141ab53;
  public let K50 : Nat64 = 0x2748774cdf8eeb99;
  public let K51 : Nat64 = 0x34b0bcb5e19b48a8;
  public let K52 : Nat64 = 0x391c0cb3c5c95a63;
  public let K53 : Nat64 = 0x4ed8aa4ae3418acb;
  public let K54 : Nat64 = 0x5b9cca4f7763e373;
  public let K55 : Nat64 = 0x682e6ff3d6b2b8a3;
  public let K56 : Nat64 = 0x748f82ee5defb2fc;
  public let K57 : Nat64 = 0x78a5636f43172f60;
  public let K58 : Nat64 = 0x84c87814a1f0ab72;
  public let K59 : Nat64 = 0x8cc702081a6439ec;
  public let K60 : Nat64 = 0x90befffa23631e28;
  public let K61 : Nat64 = 0xa4506cebde82bde9;
  public let K62 : Nat64 = 0xbef9a3f7b2c67915;
  public let K63 : Nat64 = 0xc67178f2e372532b;
  public let K64 : Nat64 = 0xca273eceea26619c;
  public let K65 : Nat64 = 0xd186b8c721c0c207;
  public let K66 : Nat64 = 0xeada7dd6cde0eb1e;
  public let K67 : Nat64 = 0xf57d4f7fee6ed178;
  public let K68 : Nat64 = 0x06f067aa72176fba;
  public let K69 : Nat64 = 0x0a637dc5a2c898a6;
  public let K70 : Nat64 = 0x113f9804bef90dae;
  public let K71 : Nat64 = 0x1b710b35131c471b;
  public let K72 : Nat64 = 0x28db77f523047d84;
  public let K73 : Nat64 = 0x32caab7b40c72493;
  public let K74 : Nat64 = 0x3c9ebe0a15c9bebc;
  public let K75 : Nat64 = 0x431d67c49c100d4c;
  public let K76 : Nat64 = 0x4cc5d4becb3e42b6;
  public let K77 : Nat64 = 0x597f299cfc657e2a;
  public let K78 : Nat64 = 0x5fcb6fab3ad6faec;
  public let K79 : Nat64 = 0x6c44198c4a475817;
};
