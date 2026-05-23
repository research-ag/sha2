/// SHA256 round constants `K00`..`K63` from FIPS 180-4 §4.2.2, exposed as individual `let`s so the unrolled compression loop can reference them by name.
module {
  /// SHA256 round constant K00.
  public let K00 : Nat32 = 0x428a2f98;
  /// SHA256 round constant K01.
  public let K01 : Nat32 = 0x71374491;
  /// SHA256 round constant K02.
  public let K02 : Nat32 = 0xb5c0fbcf;
  /// SHA256 round constant K03.
  public let K03 : Nat32 = 0xe9b5dba5;
  /// SHA256 round constant K04.
  public let K04 : Nat32 = 0x3956c25b;
  /// SHA256 round constant K05.
  public let K05 : Nat32 = 0x59f111f1;
  /// SHA256 round constant K06.
  public let K06 : Nat32 = 0x923f82a4;
  /// SHA256 round constant K07.
  public let K07 : Nat32 = 0xab1c5ed5;
  /// SHA256 round constant K08.
  public let K08 : Nat32 = 0xd807aa98;
  /// SHA256 round constant K09.
  public let K09 : Nat32 = 0x12835b01;
  /// SHA256 round constant K10.
  public let K10 : Nat32 = 0x243185be;
  /// SHA256 round constant K11.
  public let K11 : Nat32 = 0x550c7dc3;
  /// SHA256 round constant K12.
  public let K12 : Nat32 = 0x72be5d74;
  /// SHA256 round constant K13.
  public let K13 : Nat32 = 0x80deb1fe;
  /// SHA256 round constant K14.
  public let K14 : Nat32 = 0x9bdc06a7;
  /// SHA256 round constant K15.
  public let K15 : Nat32 = 0xc19bf174;
  /// SHA256 round constant K16.
  public let K16 : Nat32 = 0xe49b69c1;
  /// SHA256 round constant K17.
  public let K17 : Nat32 = 0xefbe4786;
  /// SHA256 round constant K18.
  public let K18 : Nat32 = 0x0fc19dc6;
  /// SHA256 round constant K19.
  public let K19 : Nat32 = 0x240ca1cc;
  /// SHA256 round constant K20.
  public let K20 : Nat32 = 0x2de92c6f;
  /// SHA256 round constant K21.
  public let K21 : Nat32 = 0x4a7484aa;
  /// SHA256 round constant K22.
  public let K22 : Nat32 = 0x5cb0a9dc;
  /// SHA256 round constant K23.
  public let K23 : Nat32 = 0x76f988da;
  /// SHA256 round constant K24.
  public let K24 : Nat32 = 0x983e5152;
  /// SHA256 round constant K25.
  public let K25 : Nat32 = 0xa831c66d;
  /// SHA256 round constant K26.
  public let K26 : Nat32 = 0xb00327c8;
  /// SHA256 round constant K27.
  public let K27 : Nat32 = 0xbf597fc7;
  /// SHA256 round constant K28.
  public let K28 : Nat32 = 0xc6e00bf3;
  /// SHA256 round constant K29.
  public let K29 : Nat32 = 0xd5a79147;
  /// SHA256 round constant K30.
  public let K30 : Nat32 = 0x06ca6351;
  /// SHA256 round constant K31.
  public let K31 : Nat32 = 0x14292967;
  /// SHA256 round constant K32.
  public let K32 : Nat32 = 0x27b70a85;
  /// SHA256 round constant K33.
  public let K33 : Nat32 = 0x2e1b2138;
  /// SHA256 round constant K34.
  public let K34 : Nat32 = 0x4d2c6dfc;
  /// SHA256 round constant K35.
  public let K35 : Nat32 = 0x53380d13;
  /// SHA256 round constant K36.
  public let K36 : Nat32 = 0x650a7354;
  /// SHA256 round constant K37.
  public let K37 : Nat32 = 0x766a0abb;
  /// SHA256 round constant K38.
  public let K38 : Nat32 = 0x81c2c92e;
  /// SHA256 round constant K39.
  public let K39 : Nat32 = 0x92722c85;
  /// SHA256 round constant K40.
  public let K40 : Nat32 = 0xa2bfe8a1;
  /// SHA256 round constant K41.
  public let K41 : Nat32 = 0xa81a664b;
  /// SHA256 round constant K42.
  public let K42 : Nat32 = 0xc24b8b70;
  /// SHA256 round constant K43.
  public let K43 : Nat32 = 0xc76c51a3;
  /// SHA256 round constant K44.
  public let K44 : Nat32 = 0xd192e819;
  /// SHA256 round constant K45.
  public let K45 : Nat32 = 0xd6990624;
  /// SHA256 round constant K46.
  public let K46 : Nat32 = 0xf40e3585;
  /// SHA256 round constant K47.
  public let K47 : Nat32 = 0x106aa070;
  /// SHA256 round constant K48.
  public let K48 : Nat32 = 0x19a4c116;
  /// SHA256 round constant K49.
  public let K49 : Nat32 = 0x1e376c08;
  /// SHA256 round constant K50.
  public let K50 : Nat32 = 0x2748774c;
  /// SHA256 round constant K51.
  public let K51 : Nat32 = 0x34b0bcb5;
  /// SHA256 round constant K52.
  public let K52 : Nat32 = 0x391c0cb3;
  /// SHA256 round constant K53.
  public let K53 : Nat32 = 0x4ed8aa4a;
  /// SHA256 round constant K54.
  public let K54 : Nat32 = 0x5b9cca4f;
  /// SHA256 round constant K55.
  public let K55 : Nat32 = 0x682e6ff3;
  /// SHA256 round constant K56.
  public let K56 : Nat32 = 0x748f82ee;
  /// SHA256 round constant K57.
  public let K57 : Nat32 = 0x78a5636f;
  /// SHA256 round constant K58.
  public let K58 : Nat32 = 0x84c87814;
  /// SHA256 round constant K59.
  public let K59 : Nat32 = 0x8cc70208;
  /// SHA256 round constant K60.
  public let K60 : Nat32 = 0x90befffa;
  /// SHA256 round constant K61.
  public let K61 : Nat32 = 0xa4506ceb;
  /// SHA256 round constant K62.
  public let K62 : Nat32 = 0xbef9a3f7;
  /// SHA256 round constant K63.
  public let K63 : Nat32 = 0xc67178f2;
};
