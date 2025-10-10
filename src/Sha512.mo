/// Cycle-optimized Sha512 variants.
///
/// Features:
///
/// * Algorithms: `sha512_224`, `sha512_256`, `sha384`, `sha512`
/// * Input types: `Blob`, `[Nat8]`, `Iter<Nat8>`
/// * Output types: `Blob`

import Array "mo:core/Array";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import VarArray "mo:core/VarArray";
import Prim "mo:prim";

module {
  public type Algorithm = {
    #sha384;
    #sha512;
    #sha512_224;
    #sha512_256;
  };

  public type StaticSha512 = {
    msg : [Nat64];
    digest : [Nat8];
    word : Nat64;

    i_msg : Nat8;
    i_byte : Nat8;
    i_block : Nat64;

    // state variables
    s : [Nat64];
  };

  let K00 : Nat64 = 0x428a2f98d728ae22;
  let K01 : Nat64 = 0x7137449123ef65cd;
  let K02 : Nat64 = 0xb5c0fbcfec4d3b2f;
  let K03 : Nat64 = 0xe9b5dba58189dbbc;
  let K04 : Nat64 = 0x3956c25bf348b538;
  let K05 : Nat64 = 0x59f111f1b605d019;
  let K06 : Nat64 = 0x923f82a4af194f9b;
  let K07 : Nat64 = 0xab1c5ed5da6d8118;
  let K08 : Nat64 = 0xd807aa98a3030242;
  let K09 : Nat64 = 0x12835b0145706fbe;
  let K10 : Nat64 = 0x243185be4ee4b28c;
  let K11 : Nat64 = 0x550c7dc3d5ffb4e2;
  let K12 : Nat64 = 0x72be5d74f27b896f;
  let K13 : Nat64 = 0x80deb1fe3b1696b1;
  let K14 : Nat64 = 0x9bdc06a725c71235;
  let K15 : Nat64 = 0xc19bf174cf692694;
  let K16 : Nat64 = 0xe49b69c19ef14ad2;
  let K17 : Nat64 = 0xefbe4786384f25e3;
  let K18 : Nat64 = 0x0fc19dc68b8cd5b5;
  let K19 : Nat64 = 0x240ca1cc77ac9c65;
  let K20 : Nat64 = 0x2de92c6f592b0275;
  let K21 : Nat64 = 0x4a7484aa6ea6e483;
  let K22 : Nat64 = 0x5cb0a9dcbd41fbd4;
  let K23 : Nat64 = 0x76f988da831153b5;
  let K24 : Nat64 = 0x983e5152ee66dfab;
  let K25 : Nat64 = 0xa831c66d2db43210;
  let K26 : Nat64 = 0xb00327c898fb213f;
  let K27 : Nat64 = 0xbf597fc7beef0ee4;
  let K28 : Nat64 = 0xc6e00bf33da88fc2;
  let K29 : Nat64 = 0xd5a79147930aa725;
  let K30 : Nat64 = 0x06ca6351e003826f;
  let K31 : Nat64 = 0x142929670a0e6e70;
  let K32 : Nat64 = 0x27b70a8546d22ffc;
  let K33 : Nat64 = 0x2e1b21385c26c926;
  let K34 : Nat64 = 0x4d2c6dfc5ac42aed;
  let K35 : Nat64 = 0x53380d139d95b3df;
  let K36 : Nat64 = 0x650a73548baf63de;
  let K37 : Nat64 = 0x766a0abb3c77b2a8;
  let K38 : Nat64 = 0x81c2c92e47edaee6;
  let K39 : Nat64 = 0x92722c851482353b;
  let K40 : Nat64 = 0xa2bfe8a14cf10364;
  let K41 : Nat64 = 0xa81a664bbc423001;
  let K42 : Nat64 = 0xc24b8b70d0f89791;
  let K43 : Nat64 = 0xc76c51a30654be30;
  let K44 : Nat64 = 0xd192e819d6ef5218;
  let K45 : Nat64 = 0xd69906245565a910;
  let K46 : Nat64 = 0xf40e35855771202a;
  let K47 : Nat64 = 0x106aa07032bbd1b8;
  let K48 : Nat64 = 0x19a4c116b8d2d0c8;
  let K49 : Nat64 = 0x1e376c085141ab53;
  let K50 : Nat64 = 0x2748774cdf8eeb99;
  let K51 : Nat64 = 0x34b0bcb5e19b48a8;
  let K52 : Nat64 = 0x391c0cb3c5c95a63;
  let K53 : Nat64 = 0x4ed8aa4ae3418acb;
  let K54 : Nat64 = 0x5b9cca4f7763e373;
  let K55 : Nat64 = 0x682e6ff3d6b2b8a3;
  let K56 : Nat64 = 0x748f82ee5defb2fc;
  let K57 : Nat64 = 0x78a5636f43172f60;
  let K58 : Nat64 = 0x84c87814a1f0ab72;
  let K59 : Nat64 = 0x8cc702081a6439ec;
  let K60 : Nat64 = 0x90befffa23631e28;
  let K61 : Nat64 = 0xa4506cebde82bde9;
  let K62 : Nat64 = 0xbef9a3f7b2c67915;
  let K63 : Nat64 = 0xc67178f2e372532b;
  let K64 : Nat64 = 0xca273eceea26619c;
  let K65 : Nat64 = 0xd186b8c721c0c207;
  let K66 : Nat64 = 0xeada7dd6cde0eb1e;
  let K67 : Nat64 = 0xf57d4f7fee6ed178;
  let K68 : Nat64 = 0x06f067aa72176fba;
  let K69 : Nat64 = 0x0a637dc5a2c898a6;
  let K70 : Nat64 = 0x113f9804bef90dae;
  let K71 : Nat64 = 0x1b710b35131c471b;
  let K72 : Nat64 = 0x28db77f523047d84;
  let K73 : Nat64 = 0x32caab7b40c72493;
  let K74 : Nat64 = 0x3c9ebe0a15c9bebc;
  let K75 : Nat64 = 0x431d67c49c100d4c;
  let K76 : Nat64 = 0x4cc5d4becb3e42b6;
  let K77 : Nat64 = 0x597f299cfc657e2a;
  let K78 : Nat64 = 0x5fcb6fab3ad6faec;
  let K79 : Nat64 = 0x6c44198c4a475817;

  let ivs : [[Nat64]] = [
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

  let rot = Nat64.bitrotRight;

  let nat32To64 = Prim.nat32ToNat64;
  let nat16To32 = Prim.nat16ToNat32;
  let nat8To16 = Prim.nat8ToNat16;

  public class Digest(algo_ : Algorithm) {
    let (sum_bytes, iv) = switch (algo_) {
      case (#sha512_224) { (28, 0) };
      case (#sha512_256) { (32, 1) };
      case (#sha384) { (48, 2) };
      case (#sha512) { (64, 3) };
    };

    public func algo() : Algorithm = algo_;

    var s0 : Nat64 = 0;
    var s1 : Nat64 = 0;
    var s2 : Nat64 = 0;
    var s3 : Nat64 = 0;
    var s4 : Nat64 = 0;
    var s5 : Nat64 = 0;
    var s6 : Nat64 = 0;
    var s7 : Nat64 = 0;

    let msg : [var Nat64] = VarArray.repeat<Nat64>(0, 80);
    let digest = VarArray.repeat<Nat8>(0, sum_bytes);
    var word : Nat64 = 0;

    var i_msg : Nat8 = 0;
    var i_byte : Nat8 = 8;
    var i_block : Nat64 = 0;

    public func reset() {
      i_msg := 0;
      i_byte := 8;
      i_block := 0;
      s0 := ivs[iv][0];
      s1 := ivs[iv][1];
      s2 := ivs[iv][2];
      s3 := ivs[iv][3];
      s4 := ivs[iv][4];
      s5 := ivs[iv][5];
      s6 := ivs[iv][6];
      s7 := ivs[iv][7];
    };

    reset();

    private func writeByte(val : Nat8) : () {
      word := (word << 8) ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(val)));
      i_byte -%= 1;
      if (i_byte == 0) {
        msg[Nat8.toNat(i_msg)] := word;
        word := 0;
        i_byte := 8;
        i_msg +%= 1;
        if (i_msg == 16) {
          process_block_from_buffer();
          i_msg := 0;
          i_block +%= 1;
        };
      };
    };

    // We must be at a word boundary, i.e. i_byte must be equal to 8
    private func writeWord(val : Nat64) : () {
      assert (i_byte == 8);
      msg[Nat8.toNat(i_msg)] := val;
      i_msg +%= 1;
      if (i_msg == 16) {
        process_block_from_buffer();
        i_msg := 0;
        i_block +%= 1;
      };
    };

    public func share() : StaticSha512 = {
      msg = Array.fromVarArray(msg);
      digest = Array.fromVarArray(digest);
      word;
      i_msg;
      i_byte;
      i_block;
      s = [s0, s1, s2, s3, s4, s5, s6, s7];
    };

    public func unshare(state : StaticSha512) {
      assert msg.size() == state.msg.size();
      assert digest.size() == state.digest.size();

      for (i in msg.keys()) {
        msg[i] := state.msg[i];
      };

      for (i in digest.keys()) {
        digest[i] := state.digest[i];
      };

      word := state.word;
      i_msg := state.i_msg;
      i_byte := state.i_byte;
      i_block := state.i_block;

      s0 := state.s[0];
      s1 := state.s[1];
      s2 := state.s[2];
      s3 := state.s[3];
      s4 := state.s[4];
      s5 := state.s[5];
      s6 := state.s[6];
      s7 := state.s[7];
    };

    private func process_block_from_buffer() : () {
      // Below is an inlined and unrolled version of this code:
      // for ((i, j, k, l, m) in expansion_rounds.vals()) {
      //   // (j,k,l,m) = (i+1,i+9,i+14,i+16)
      //   let (v0, v1) = (msg[j], msg[l]);
      //   let s0 = rot(v0, 07) ^ rot(v0, 18) ^ (v0 >> 03);
      //   let s1 = rot(v1, 17) ^ rot(v1, 19) ^ (v1 >> 10);
      //   msg[m] := msg[i] +% s0 +% msg[k] +% s1;
      // };
      let w00 = msg[0];
      let w01 = msg[1];
      let w02 = msg[2];
      let w03 = msg[3];
      let w04 = msg[4];
      let w05 = msg[5];
      let w06 = msg[6];
      let w07 = msg[7];
      let w08 = msg[8];
      let w09 = msg[9];
      let w10 = msg[10];
      let w11 = msg[11];
      let w12 = msg[12];
      let w13 = msg[13];
      let w14 = msg[14];
      let w15 = msg[15];
      let w16 = w00 +% rot(w01, 01) ^ rot(w01, 08) ^ (w01 >> 07) +% w09 +% rot(w14, 19) ^ rot(w14, 61) ^ (w14 >> 06);
      let w17 = w01 +% rot(w02, 01) ^ rot(w02, 08) ^ (w02 >> 07) +% w10 +% rot(w15, 19) ^ rot(w15, 61) ^ (w15 >> 06);
      let w18 = w02 +% rot(w03, 01) ^ rot(w03, 08) ^ (w03 >> 07) +% w11 +% rot(w16, 19) ^ rot(w16, 61) ^ (w16 >> 06);
      let w19 = w03 +% rot(w04, 01) ^ rot(w04, 08) ^ (w04 >> 07) +% w12 +% rot(w17, 19) ^ rot(w17, 61) ^ (w17 >> 06);
      let w20 = w04 +% rot(w05, 01) ^ rot(w05, 08) ^ (w05 >> 07) +% w13 +% rot(w18, 19) ^ rot(w18, 61) ^ (w18 >> 06);
      let w21 = w05 +% rot(w06, 01) ^ rot(w06, 08) ^ (w06 >> 07) +% w14 +% rot(w19, 19) ^ rot(w19, 61) ^ (w19 >> 06);
      let w22 = w06 +% rot(w07, 01) ^ rot(w07, 08) ^ (w07 >> 07) +% w15 +% rot(w20, 19) ^ rot(w20, 61) ^ (w20 >> 06);
      let w23 = w07 +% rot(w08, 01) ^ rot(w08, 08) ^ (w08 >> 07) +% w16 +% rot(w21, 19) ^ rot(w21, 61) ^ (w21 >> 06);
      let w24 = w08 +% rot(w09, 01) ^ rot(w09, 08) ^ (w09 >> 07) +% w17 +% rot(w22, 19) ^ rot(w22, 61) ^ (w22 >> 06);
      let w25 = w09 +% rot(w10, 01) ^ rot(w10, 08) ^ (w10 >> 07) +% w18 +% rot(w23, 19) ^ rot(w23, 61) ^ (w23 >> 06);
      let w26 = w10 +% rot(w11, 01) ^ rot(w11, 08) ^ (w11 >> 07) +% w19 +% rot(w24, 19) ^ rot(w24, 61) ^ (w24 >> 06);
      let w27 = w11 +% rot(w12, 01) ^ rot(w12, 08) ^ (w12 >> 07) +% w20 +% rot(w25, 19) ^ rot(w25, 61) ^ (w25 >> 06);
      let w28 = w12 +% rot(w13, 01) ^ rot(w13, 08) ^ (w13 >> 07) +% w21 +% rot(w26, 19) ^ rot(w26, 61) ^ (w26 >> 06);
      let w29 = w13 +% rot(w14, 01) ^ rot(w14, 08) ^ (w14 >> 07) +% w22 +% rot(w27, 19) ^ rot(w27, 61) ^ (w27 >> 06);
      let w30 = w14 +% rot(w15, 01) ^ rot(w15, 08) ^ (w15 >> 07) +% w23 +% rot(w28, 19) ^ rot(w28, 61) ^ (w28 >> 06);
      let w31 = w15 +% rot(w16, 01) ^ rot(w16, 08) ^ (w16 >> 07) +% w24 +% rot(w29, 19) ^ rot(w29, 61) ^ (w29 >> 06);
      let w32 = w16 +% rot(w17, 01) ^ rot(w17, 08) ^ (w17 >> 07) +% w25 +% rot(w30, 19) ^ rot(w30, 61) ^ (w30 >> 06);
      let w33 = w17 +% rot(w18, 01) ^ rot(w18, 08) ^ (w18 >> 07) +% w26 +% rot(w31, 19) ^ rot(w31, 61) ^ (w31 >> 06);
      let w34 = w18 +% rot(w19, 01) ^ rot(w19, 08) ^ (w19 >> 07) +% w27 +% rot(w32, 19) ^ rot(w32, 61) ^ (w32 >> 06);
      let w35 = w19 +% rot(w20, 01) ^ rot(w20, 08) ^ (w20 >> 07) +% w28 +% rot(w33, 19) ^ rot(w33, 61) ^ (w33 >> 06);
      let w36 = w20 +% rot(w21, 01) ^ rot(w21, 08) ^ (w21 >> 07) +% w29 +% rot(w34, 19) ^ rot(w34, 61) ^ (w34 >> 06);
      let w37 = w21 +% rot(w22, 01) ^ rot(w22, 08) ^ (w22 >> 07) +% w30 +% rot(w35, 19) ^ rot(w35, 61) ^ (w35 >> 06);
      let w38 = w22 +% rot(w23, 01) ^ rot(w23, 08) ^ (w23 >> 07) +% w31 +% rot(w36, 19) ^ rot(w36, 61) ^ (w36 >> 06);
      let w39 = w23 +% rot(w24, 01) ^ rot(w24, 08) ^ (w24 >> 07) +% w32 +% rot(w37, 19) ^ rot(w37, 61) ^ (w37 >> 06);
      let w40 = w24 +% rot(w25, 01) ^ rot(w25, 08) ^ (w25 >> 07) +% w33 +% rot(w38, 19) ^ rot(w38, 61) ^ (w38 >> 06);
      let w41 = w25 +% rot(w26, 01) ^ rot(w26, 08) ^ (w26 >> 07) +% w34 +% rot(w39, 19) ^ rot(w39, 61) ^ (w39 >> 06);
      let w42 = w26 +% rot(w27, 01) ^ rot(w27, 08) ^ (w27 >> 07) +% w35 +% rot(w40, 19) ^ rot(w40, 61) ^ (w40 >> 06);
      let w43 = w27 +% rot(w28, 01) ^ rot(w28, 08) ^ (w28 >> 07) +% w36 +% rot(w41, 19) ^ rot(w41, 61) ^ (w41 >> 06);
      let w44 = w28 +% rot(w29, 01) ^ rot(w29, 08) ^ (w29 >> 07) +% w37 +% rot(w42, 19) ^ rot(w42, 61) ^ (w42 >> 06);
      let w45 = w29 +% rot(w30, 01) ^ rot(w30, 08) ^ (w30 >> 07) +% w38 +% rot(w43, 19) ^ rot(w43, 61) ^ (w43 >> 06);
      let w46 = w30 +% rot(w31, 01) ^ rot(w31, 08) ^ (w31 >> 07) +% w39 +% rot(w44, 19) ^ rot(w44, 61) ^ (w44 >> 06);
      let w47 = w31 +% rot(w32, 01) ^ rot(w32, 08) ^ (w32 >> 07) +% w40 +% rot(w45, 19) ^ rot(w45, 61) ^ (w45 >> 06);
      let w48 = w32 +% rot(w33, 01) ^ rot(w33, 08) ^ (w33 >> 07) +% w41 +% rot(w46, 19) ^ rot(w46, 61) ^ (w46 >> 06);
      let w49 = w33 +% rot(w34, 01) ^ rot(w34, 08) ^ (w34 >> 07) +% w42 +% rot(w47, 19) ^ rot(w47, 61) ^ (w47 >> 06);
      let w50 = w34 +% rot(w35, 01) ^ rot(w35, 08) ^ (w35 >> 07) +% w43 +% rot(w48, 19) ^ rot(w48, 61) ^ (w48 >> 06);
      let w51 = w35 +% rot(w36, 01) ^ rot(w36, 08) ^ (w36 >> 07) +% w44 +% rot(w49, 19) ^ rot(w49, 61) ^ (w49 >> 06);
      let w52 = w36 +% rot(w37, 01) ^ rot(w37, 08) ^ (w37 >> 07) +% w45 +% rot(w50, 19) ^ rot(w50, 61) ^ (w50 >> 06);
      let w53 = w37 +% rot(w38, 01) ^ rot(w38, 08) ^ (w38 >> 07) +% w46 +% rot(w51, 19) ^ rot(w51, 61) ^ (w51 >> 06);
      let w54 = w38 +% rot(w39, 01) ^ rot(w39, 08) ^ (w39 >> 07) +% w47 +% rot(w52, 19) ^ rot(w52, 61) ^ (w52 >> 06);
      let w55 = w39 +% rot(w40, 01) ^ rot(w40, 08) ^ (w40 >> 07) +% w48 +% rot(w53, 19) ^ rot(w53, 61) ^ (w53 >> 06);
      let w56 = w40 +% rot(w41, 01) ^ rot(w41, 08) ^ (w41 >> 07) +% w49 +% rot(w54, 19) ^ rot(w54, 61) ^ (w54 >> 06);
      let w57 = w41 +% rot(w42, 01) ^ rot(w42, 08) ^ (w42 >> 07) +% w50 +% rot(w55, 19) ^ rot(w55, 61) ^ (w55 >> 06);
      let w58 = w42 +% rot(w43, 01) ^ rot(w43, 08) ^ (w43 >> 07) +% w51 +% rot(w56, 19) ^ rot(w56, 61) ^ (w56 >> 06);
      let w59 = w43 +% rot(w44, 01) ^ rot(w44, 08) ^ (w44 >> 07) +% w52 +% rot(w57, 19) ^ rot(w57, 61) ^ (w57 >> 06);
      let w60 = w44 +% rot(w45, 01) ^ rot(w45, 08) ^ (w45 >> 07) +% w53 +% rot(w58, 19) ^ rot(w58, 61) ^ (w58 >> 06);
      let w61 = w45 +% rot(w46, 01) ^ rot(w46, 08) ^ (w46 >> 07) +% w54 +% rot(w59, 19) ^ rot(w59, 61) ^ (w59 >> 06);
      let w62 = w46 +% rot(w47, 01) ^ rot(w47, 08) ^ (w47 >> 07) +% w55 +% rot(w60, 19) ^ rot(w60, 61) ^ (w60 >> 06);
      let w63 = w47 +% rot(w48, 01) ^ rot(w48, 08) ^ (w48 >> 07) +% w56 +% rot(w61, 19) ^ rot(w61, 61) ^ (w61 >> 06);
      let w64 = w48 +% rot(w49, 01) ^ rot(w49, 08) ^ (w49 >> 07) +% w57 +% rot(w62, 19) ^ rot(w62, 61) ^ (w62 >> 06);
      let w65 = w49 +% rot(w50, 01) ^ rot(w50, 08) ^ (w50 >> 07) +% w58 +% rot(w63, 19) ^ rot(w63, 61) ^ (w63 >> 06);
      let w66 = w50 +% rot(w51, 01) ^ rot(w51, 08) ^ (w51 >> 07) +% w59 +% rot(w64, 19) ^ rot(w64, 61) ^ (w64 >> 06);
      let w67 = w51 +% rot(w52, 01) ^ rot(w52, 08) ^ (w52 >> 07) +% w60 +% rot(w65, 19) ^ rot(w65, 61) ^ (w65 >> 06);
      let w68 = w52 +% rot(w53, 01) ^ rot(w53, 08) ^ (w53 >> 07) +% w61 +% rot(w66, 19) ^ rot(w66, 61) ^ (w66 >> 06);
      let w69 = w53 +% rot(w54, 01) ^ rot(w54, 08) ^ (w54 >> 07) +% w62 +% rot(w67, 19) ^ rot(w67, 61) ^ (w67 >> 06);
      let w70 = w54 +% rot(w55, 01) ^ rot(w55, 08) ^ (w55 >> 07) +% w63 +% rot(w68, 19) ^ rot(w68, 61) ^ (w68 >> 06);
      let w71 = w55 +% rot(w56, 01) ^ rot(w56, 08) ^ (w56 >> 07) +% w64 +% rot(w69, 19) ^ rot(w69, 61) ^ (w69 >> 06);
      let w72 = w56 +% rot(w57, 01) ^ rot(w57, 08) ^ (w57 >> 07) +% w65 +% rot(w70, 19) ^ rot(w70, 61) ^ (w70 >> 06);
      let w73 = w57 +% rot(w58, 01) ^ rot(w58, 08) ^ (w58 >> 07) +% w66 +% rot(w71, 19) ^ rot(w71, 61) ^ (w71 >> 06);
      let w74 = w58 +% rot(w59, 01) ^ rot(w59, 08) ^ (w59 >> 07) +% w67 +% rot(w72, 19) ^ rot(w72, 61) ^ (w72 >> 06);
      let w75 = w59 +% rot(w60, 01) ^ rot(w60, 08) ^ (w60 >> 07) +% w68 +% rot(w73, 19) ^ rot(w73, 61) ^ (w73 >> 06);
      let w76 = w60 +% rot(w61, 01) ^ rot(w61, 08) ^ (w61 >> 07) +% w69 +% rot(w74, 19) ^ rot(w74, 61) ^ (w74 >> 06);
      let w77 = w61 +% rot(w62, 01) ^ rot(w62, 08) ^ (w62 >> 07) +% w70 +% rot(w75, 19) ^ rot(w75, 61) ^ (w75 >> 06);
      let w78 = w62 +% rot(w63, 01) ^ rot(w63, 08) ^ (w63 >> 07) +% w71 +% rot(w76, 19) ^ rot(w76, 61) ^ (w76 >> 06);
      let w79 = w63 +% rot(w64, 01) ^ rot(w64, 08) ^ (w64 >> 07) +% w72 +% rot(w77, 19) ^ rot(w77, 61) ^ (w77 >> 06);

      // compress
      var a = s0;
      var b = s1;
      var c = s2;
      var d = s3;
      var e = s4;
      var f = s5;
      var g = s6;
      var h = s7;

      // Below is an inlined and unrolled version of this code:
      // for (i in compression_rounds.keys()) {
      //   let ch = (e & f) ^ (^ e & g);
      //   let maj = (a & b) ^ (a & c) ^ (b & c);
      //   let sigma0 = rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      //   let sigma1 = rot(e, 06) ^ rot(e, 11) ^ rot(e, 25);
      //   let t = h +% K[i] +% msg[i] +% ch +% sigma1;
      //   h := g;
      //   g := f;
      //   f := e;
      //   e := d +% t;
      //   d := c;
      //   c := b;
      //   b := a;
      //   a := t +% maj +% sigma0;
      // };

      var t = 0 : Nat64;
      t := h +% K00 +% w00 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K01 +% w01 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K02 +% w02 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K03 +% w03 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K04 +% w04 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K05 +% w05 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K06 +% w06 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K07 +% w07 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K08 +% w08 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K09 +% w09 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K10 +% w10 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K11 +% w11 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K12 +% w12 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K13 +% w13 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K14 +% w14 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K15 +% w15 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K16 +% w16 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K17 +% w17 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K18 +% w18 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K19 +% w19 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K20 +% w20 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K21 +% w21 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K22 +% w22 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K23 +% w23 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K24 +% w24 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K25 +% w25 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K26 +% w26 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K27 +% w27 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K28 +% w28 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K29 +% w29 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K30 +% w30 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K31 +% w31 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K32 +% w32 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K33 +% w33 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K34 +% w34 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K35 +% w35 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K36 +% w36 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K37 +% w37 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K38 +% w38 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K39 +% w39 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K40 +% w40 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K41 +% w41 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K42 +% w42 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K43 +% w43 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K44 +% w44 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K45 +% w45 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K46 +% w46 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K47 +% w47 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K48 +% w48 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K49 +% w49 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K50 +% w50 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K51 +% w51 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K52 +% w52 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K53 +% w53 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K54 +% w54 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K55 +% w55 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K56 +% w56 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K57 +% w57 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K58 +% w58 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K59 +% w59 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K60 +% w60 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K61 +% w61 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K62 +% w62 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K63 +% w63 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K64 +% w64 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K65 +% w65 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K66 +% w66 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K67 +% w67 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K68 +% w68 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K69 +% w69 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K70 +% w70 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K71 +% w71 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K72 +% w72 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K73 +% w73 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K74 +% w74 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K75 +% w75 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K76 +% w76 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K77 +% w77 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K78 +% w78 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
      t := h +% K79 +% w79 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);

      // final addition
      s0 +%= a;
      s1 +%= b;
      s2 +%= c;
      s3 +%= d;
      s4 +%= e;
      s5 +%= f;
      s6 +%= g;
      s7 +%= h;
    };

    private func process_blocks_from_blob(blob : Blob, start : Nat) : Nat {
      let s = blob.size();
      var i = start;
      // load state registers
      var a = s0;
      var b = s1;
      var c = s2;
      var d = s3;
      var e = s4;
      var f = s5;
      var g = s6;
      var h = s7;
      var t = 0 : Nat64;
      var i_max : Nat = i + ((s - i) / 128) * 128;
      while (i < i_max) {
        let a_0 = a;
        let b_0 = b;
        let c_0 = c;
        let d_0 = d;
        let e_0 = e;
        let f_0 = f;
        let g_0 = g;
        let h_0 = h;

        let w00 = nat32To64(nat16To32(nat8To16(blob[i+0]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+1]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+2]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+3]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+4]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+5]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+6]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+7])));
        let w01 = nat32To64(nat16To32(nat8To16(blob[i+8]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+9]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+10]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+11]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+12]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+13]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+14]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+15])));
        let w02 = nat32To64(nat16To32(nat8To16(blob[i+16]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+17]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+18]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+19]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+20]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+21]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+22]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+23])));
        let w03 = nat32To64(nat16To32(nat8To16(blob[i+24]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+25]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+26]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+27]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+28]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+29]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+30]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+31])));
        let w04 = nat32To64(nat16To32(nat8To16(blob[i+32]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+33]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+34]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+35]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+36]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+37]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+38]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+39])));
        let w05 = nat32To64(nat16To32(nat8To16(blob[i+40]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+41]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+42]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+43]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+44]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+45]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+46]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+47])));
        let w06 = nat32To64(nat16To32(nat8To16(blob[i+48]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+49]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+50]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+51]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+52]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+53]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+54]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+55])));
        let w07 = nat32To64(nat16To32(nat8To16(blob[i+56]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+57]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+58]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+59]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+60]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+61]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+62]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+63])));
        let w08 = nat32To64(nat16To32(nat8To16(blob[i+64]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+65]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+66]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+67]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+68]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+69]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+70]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+71])));
        let w09 = nat32To64(nat16To32(nat8To16(blob[i+72]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+73]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+74]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+75]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+76]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+77]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+78]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+79])));
        let w10 = nat32To64(nat16To32(nat8To16(blob[i+80]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+81]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+82]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+83]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+84]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+85]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+86]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+87])));
        let w11 = nat32To64(nat16To32(nat8To16(blob[i+88]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+89]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+90]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+91]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+92]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+93]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+94]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+95])));
        let w12 = nat32To64(nat16To32(nat8To16(blob[i+96]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+97]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+98]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+99]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+100]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+101]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+102]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+103])));
        let w13 = nat32To64(nat16To32(nat8To16(blob[i+104]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+105]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+106]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+107]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+108]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+109]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+110]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+111])));
        let w14 = nat32To64(nat16To32(nat8To16(blob[i+112]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+113]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+114]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+115]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+116]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+117]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+118]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+119])));
        let w15 = nat32To64(nat16To32(nat8To16(blob[i+120]))) << 56 | nat32To64(nat16To32(nat8To16(blob[i+121]))) << 48 | nat32To64(nat16To32(nat8To16(blob[i+122]))) << 40 | nat32To64(nat16To32(nat8To16(blob[i+123]))) << 32 | nat32To64(nat16To32(nat8To16(blob[i+124]))) << 24 | nat32To64(nat16To32(nat8To16(blob[i+125]))) << 16 | nat32To64(nat16To32(nat8To16(blob[i+126]))) << 8 | nat32To64(nat16To32(nat8To16(blob[i+127])));

        let w16 = w00 +% rot(w01, 01) ^ rot(w01, 08) ^ (w01 >> 07) +% w09 +% rot(w14, 19) ^ rot(w14, 61) ^ (w14 >> 06);
        let w17 = w01 +% rot(w02, 01) ^ rot(w02, 08) ^ (w02 >> 07) +% w10 +% rot(w15, 19) ^ rot(w15, 61) ^ (w15 >> 06);
        let w18 = w02 +% rot(w03, 01) ^ rot(w03, 08) ^ (w03 >> 07) +% w11 +% rot(w16, 19) ^ rot(w16, 61) ^ (w16 >> 06);
        let w19 = w03 +% rot(w04, 01) ^ rot(w04, 08) ^ (w04 >> 07) +% w12 +% rot(w17, 19) ^ rot(w17, 61) ^ (w17 >> 06);
        let w20 = w04 +% rot(w05, 01) ^ rot(w05, 08) ^ (w05 >> 07) +% w13 +% rot(w18, 19) ^ rot(w18, 61) ^ (w18 >> 06);
        let w21 = w05 +% rot(w06, 01) ^ rot(w06, 08) ^ (w06 >> 07) +% w14 +% rot(w19, 19) ^ rot(w19, 61) ^ (w19 >> 06);
        let w22 = w06 +% rot(w07, 01) ^ rot(w07, 08) ^ (w07 >> 07) +% w15 +% rot(w20, 19) ^ rot(w20, 61) ^ (w20 >> 06);
        let w23 = w07 +% rot(w08, 01) ^ rot(w08, 08) ^ (w08 >> 07) +% w16 +% rot(w21, 19) ^ rot(w21, 61) ^ (w21 >> 06);
        let w24 = w08 +% rot(w09, 01) ^ rot(w09, 08) ^ (w09 >> 07) +% w17 +% rot(w22, 19) ^ rot(w22, 61) ^ (w22 >> 06);
        let w25 = w09 +% rot(w10, 01) ^ rot(w10, 08) ^ (w10 >> 07) +% w18 +% rot(w23, 19) ^ rot(w23, 61) ^ (w23 >> 06);
        let w26 = w10 +% rot(w11, 01) ^ rot(w11, 08) ^ (w11 >> 07) +% w19 +% rot(w24, 19) ^ rot(w24, 61) ^ (w24 >> 06);
        let w27 = w11 +% rot(w12, 01) ^ rot(w12, 08) ^ (w12 >> 07) +% w20 +% rot(w25, 19) ^ rot(w25, 61) ^ (w25 >> 06);
        let w28 = w12 +% rot(w13, 01) ^ rot(w13, 08) ^ (w13 >> 07) +% w21 +% rot(w26, 19) ^ rot(w26, 61) ^ (w26 >> 06);
        let w29 = w13 +% rot(w14, 01) ^ rot(w14, 08) ^ (w14 >> 07) +% w22 +% rot(w27, 19) ^ rot(w27, 61) ^ (w27 >> 06);
        let w30 = w14 +% rot(w15, 01) ^ rot(w15, 08) ^ (w15 >> 07) +% w23 +% rot(w28, 19) ^ rot(w28, 61) ^ (w28 >> 06);
        let w31 = w15 +% rot(w16, 01) ^ rot(w16, 08) ^ (w16 >> 07) +% w24 +% rot(w29, 19) ^ rot(w29, 61) ^ (w29 >> 06);
        let w32 = w16 +% rot(w17, 01) ^ rot(w17, 08) ^ (w17 >> 07) +% w25 +% rot(w30, 19) ^ rot(w30, 61) ^ (w30 >> 06);
        let w33 = w17 +% rot(w18, 01) ^ rot(w18, 08) ^ (w18 >> 07) +% w26 +% rot(w31, 19) ^ rot(w31, 61) ^ (w31 >> 06);
        let w34 = w18 +% rot(w19, 01) ^ rot(w19, 08) ^ (w19 >> 07) +% w27 +% rot(w32, 19) ^ rot(w32, 61) ^ (w32 >> 06);
        let w35 = w19 +% rot(w20, 01) ^ rot(w20, 08) ^ (w20 >> 07) +% w28 +% rot(w33, 19) ^ rot(w33, 61) ^ (w33 >> 06);
        let w36 = w20 +% rot(w21, 01) ^ rot(w21, 08) ^ (w21 >> 07) +% w29 +% rot(w34, 19) ^ rot(w34, 61) ^ (w34 >> 06);
        let w37 = w21 +% rot(w22, 01) ^ rot(w22, 08) ^ (w22 >> 07) +% w30 +% rot(w35, 19) ^ rot(w35, 61) ^ (w35 >> 06);
        let w38 = w22 +% rot(w23, 01) ^ rot(w23, 08) ^ (w23 >> 07) +% w31 +% rot(w36, 19) ^ rot(w36, 61) ^ (w36 >> 06);
        let w39 = w23 +% rot(w24, 01) ^ rot(w24, 08) ^ (w24 >> 07) +% w32 +% rot(w37, 19) ^ rot(w37, 61) ^ (w37 >> 06);
        let w40 = w24 +% rot(w25, 01) ^ rot(w25, 08) ^ (w25 >> 07) +% w33 +% rot(w38, 19) ^ rot(w38, 61) ^ (w38 >> 06);
        let w41 = w25 +% rot(w26, 01) ^ rot(w26, 08) ^ (w26 >> 07) +% w34 +% rot(w39, 19) ^ rot(w39, 61) ^ (w39 >> 06);
        let w42 = w26 +% rot(w27, 01) ^ rot(w27, 08) ^ (w27 >> 07) +% w35 +% rot(w40, 19) ^ rot(w40, 61) ^ (w40 >> 06);
        let w43 = w27 +% rot(w28, 01) ^ rot(w28, 08) ^ (w28 >> 07) +% w36 +% rot(w41, 19) ^ rot(w41, 61) ^ (w41 >> 06);
        let w44 = w28 +% rot(w29, 01) ^ rot(w29, 08) ^ (w29 >> 07) +% w37 +% rot(w42, 19) ^ rot(w42, 61) ^ (w42 >> 06);
        let w45 = w29 +% rot(w30, 01) ^ rot(w30, 08) ^ (w30 >> 07) +% w38 +% rot(w43, 19) ^ rot(w43, 61) ^ (w43 >> 06);
        let w46 = w30 +% rot(w31, 01) ^ rot(w31, 08) ^ (w31 >> 07) +% w39 +% rot(w44, 19) ^ rot(w44, 61) ^ (w44 >> 06);
        let w47 = w31 +% rot(w32, 01) ^ rot(w32, 08) ^ (w32 >> 07) +% w40 +% rot(w45, 19) ^ rot(w45, 61) ^ (w45 >> 06);
        let w48 = w32 +% rot(w33, 01) ^ rot(w33, 08) ^ (w33 >> 07) +% w41 +% rot(w46, 19) ^ rot(w46, 61) ^ (w46 >> 06);
        let w49 = w33 +% rot(w34, 01) ^ rot(w34, 08) ^ (w34 >> 07) +% w42 +% rot(w47, 19) ^ rot(w47, 61) ^ (w47 >> 06);
        let w50 = w34 +% rot(w35, 01) ^ rot(w35, 08) ^ (w35 >> 07) +% w43 +% rot(w48, 19) ^ rot(w48, 61) ^ (w48 >> 06);
        let w51 = w35 +% rot(w36, 01) ^ rot(w36, 08) ^ (w36 >> 07) +% w44 +% rot(w49, 19) ^ rot(w49, 61) ^ (w49 >> 06);
        let w52 = w36 +% rot(w37, 01) ^ rot(w37, 08) ^ (w37 >> 07) +% w45 +% rot(w50, 19) ^ rot(w50, 61) ^ (w50 >> 06);
        let w53 = w37 +% rot(w38, 01) ^ rot(w38, 08) ^ (w38 >> 07) +% w46 +% rot(w51, 19) ^ rot(w51, 61) ^ (w51 >> 06);
        let w54 = w38 +% rot(w39, 01) ^ rot(w39, 08) ^ (w39 >> 07) +% w47 +% rot(w52, 19) ^ rot(w52, 61) ^ (w52 >> 06);
        let w55 = w39 +% rot(w40, 01) ^ rot(w40, 08) ^ (w40 >> 07) +% w48 +% rot(w53, 19) ^ rot(w53, 61) ^ (w53 >> 06);
        let w56 = w40 +% rot(w41, 01) ^ rot(w41, 08) ^ (w41 >> 07) +% w49 +% rot(w54, 19) ^ rot(w54, 61) ^ (w54 >> 06);
        let w57 = w41 +% rot(w42, 01) ^ rot(w42, 08) ^ (w42 >> 07) +% w50 +% rot(w55, 19) ^ rot(w55, 61) ^ (w55 >> 06);
        let w58 = w42 +% rot(w43, 01) ^ rot(w43, 08) ^ (w43 >> 07) +% w51 +% rot(w56, 19) ^ rot(w56, 61) ^ (w56 >> 06);
        let w59 = w43 +% rot(w44, 01) ^ rot(w44, 08) ^ (w44 >> 07) +% w52 +% rot(w57, 19) ^ rot(w57, 61) ^ (w57 >> 06);
        let w60 = w44 +% rot(w45, 01) ^ rot(w45, 08) ^ (w45 >> 07) +% w53 +% rot(w58, 19) ^ rot(w58, 61) ^ (w58 >> 06);
        let w61 = w45 +% rot(w46, 01) ^ rot(w46, 08) ^ (w46 >> 07) +% w54 +% rot(w59, 19) ^ rot(w59, 61) ^ (w59 >> 06);
        let w62 = w46 +% rot(w47, 01) ^ rot(w47, 08) ^ (w47 >> 07) +% w55 +% rot(w60, 19) ^ rot(w60, 61) ^ (w60 >> 06);
        let w63 = w47 +% rot(w48, 01) ^ rot(w48, 08) ^ (w48 >> 07) +% w56 +% rot(w61, 19) ^ rot(w61, 61) ^ (w61 >> 06);
        let w64 = w48 +% rot(w49, 01) ^ rot(w49, 08) ^ (w49 >> 07) +% w57 +% rot(w62, 19) ^ rot(w62, 61) ^ (w62 >> 06);
        let w65 = w49 +% rot(w50, 01) ^ rot(w50, 08) ^ (w50 >> 07) +% w58 +% rot(w63, 19) ^ rot(w63, 61) ^ (w63 >> 06);
        let w66 = w50 +% rot(w51, 01) ^ rot(w51, 08) ^ (w51 >> 07) +% w59 +% rot(w64, 19) ^ rot(w64, 61) ^ (w64 >> 06);
        let w67 = w51 +% rot(w52, 01) ^ rot(w52, 08) ^ (w52 >> 07) +% w60 +% rot(w65, 19) ^ rot(w65, 61) ^ (w65 >> 06);
        let w68 = w52 +% rot(w53, 01) ^ rot(w53, 08) ^ (w53 >> 07) +% w61 +% rot(w66, 19) ^ rot(w66, 61) ^ (w66 >> 06);
        let w69 = w53 +% rot(w54, 01) ^ rot(w54, 08) ^ (w54 >> 07) +% w62 +% rot(w67, 19) ^ rot(w67, 61) ^ (w67 >> 06);
        let w70 = w54 +% rot(w55, 01) ^ rot(w55, 08) ^ (w55 >> 07) +% w63 +% rot(w68, 19) ^ rot(w68, 61) ^ (w68 >> 06);
        let w71 = w55 +% rot(w56, 01) ^ rot(w56, 08) ^ (w56 >> 07) +% w64 +% rot(w69, 19) ^ rot(w69, 61) ^ (w69 >> 06);
        let w72 = w56 +% rot(w57, 01) ^ rot(w57, 08) ^ (w57 >> 07) +% w65 +% rot(w70, 19) ^ rot(w70, 61) ^ (w70 >> 06);
        let w73 = w57 +% rot(w58, 01) ^ rot(w58, 08) ^ (w58 >> 07) +% w66 +% rot(w71, 19) ^ rot(w71, 61) ^ (w71 >> 06);
        let w74 = w58 +% rot(w59, 01) ^ rot(w59, 08) ^ (w59 >> 07) +% w67 +% rot(w72, 19) ^ rot(w72, 61) ^ (w72 >> 06);
        let w75 = w59 +% rot(w60, 01) ^ rot(w60, 08) ^ (w60 >> 07) +% w68 +% rot(w73, 19) ^ rot(w73, 61) ^ (w73 >> 06);
        let w76 = w60 +% rot(w61, 01) ^ rot(w61, 08) ^ (w61 >> 07) +% w69 +% rot(w74, 19) ^ rot(w74, 61) ^ (w74 >> 06);
        let w77 = w61 +% rot(w62, 01) ^ rot(w62, 08) ^ (w62 >> 07) +% w70 +% rot(w75, 19) ^ rot(w75, 61) ^ (w75 >> 06);
        let w78 = w62 +% rot(w63, 01) ^ rot(w63, 08) ^ (w63 >> 07) +% w71 +% rot(w76, 19) ^ rot(w76, 61) ^ (w76 >> 06);
        let w79 = w63 +% rot(w64, 01) ^ rot(w64, 08) ^ (w64 >> 07) +% w72 +% rot(w77, 19) ^ rot(w77, 61) ^ (w77 >> 06);

        t := h +% K00 +% w00 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K01 +% w01 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K02 +% w02 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K03 +% w03 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K04 +% w04 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K05 +% w05 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K06 +% w06 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K07 +% w07 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K08 +% w08 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K09 +% w09 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K10 +% w10 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K11 +% w11 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K12 +% w12 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K13 +% w13 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K14 +% w14 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K15 +% w15 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K16 +% w16 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K17 +% w17 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K18 +% w18 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K19 +% w19 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K20 +% w20 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K21 +% w21 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K22 +% w22 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K23 +% w23 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K24 +% w24 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K25 +% w25 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K26 +% w26 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K27 +% w27 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K28 +% w28 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K29 +% w29 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K30 +% w30 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K31 +% w31 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K32 +% w32 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K33 +% w33 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K34 +% w34 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K35 +% w35 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K36 +% w36 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K37 +% w37 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K38 +% w38 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K39 +% w39 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K40 +% w40 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K41 +% w41 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K42 +% w42 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K43 +% w43 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K44 +% w44 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K45 +% w45 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K46 +% w46 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K47 +% w47 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K48 +% w48 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K49 +% w49 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K50 +% w50 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K51 +% w51 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K52 +% w52 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K53 +% w53 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K54 +% w54 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K55 +% w55 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K56 +% w56 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K57 +% w57 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K58 +% w58 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K59 +% w59 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K60 +% w60 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K61 +% w61 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K62 +% w62 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K63 +% w63 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K64 +% w64 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K65 +% w65 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K66 +% w66 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K67 +% w67 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K68 +% w68 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K69 +% w69 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K70 +% w70 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K71 +% w71 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K72 +% w72 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K73 +% w73 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K74 +% w74 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K75 +% w75 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K76 +% w76 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K77 +% w77 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K78 +% w78 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K79 +% w79 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);

        // final addition
        a +%= a_0;
        b +%= b_0;
        c +%= c_0;
        d +%= d_0;
        e +%= e_0;
        f +%= f_0;
        g +%= g_0;
        h +%= h_0;

        // counters
        i += 128;
        i_block +%= 1;
      };
      // write state back to registers
      s0 := a;
      s1 := b;
      s2 := c;
      s3 := d;
      s4 := e;
      s5 := f;
      s6 := g;
      s7 := h;

      return i
    };
    private func process_blocks_from_arr(arr : [Nat8], start : Nat) : Nat {
      let s = arr.size();
      var i = start;
      // load state registers
      var a = s0;
      var b = s1;
      var c = s2;
      var d = s3;
      var e = s4;
      var f = s5;
      var g = s6;
      var h = s7;
      var t = 0 : Nat64;
      var i_max : Nat = i + ((s - i) / 128) * 128;
      while (i < i_max) {
        let a_0 = a;
        let b_0 = b;
        let c_0 = c;
        let d_0 = d;
        let e_0 = e;
        let f_0 = f;
        let g_0 = g;
        let h_0 = h;

        let w00 = nat32To64(nat16To32(nat8To16(arr[i+0]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+1]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+2]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+3]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+4]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+5]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+6]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+7])));
        let w01 = nat32To64(nat16To32(nat8To16(arr[i+8]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+9]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+10]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+11]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+12]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+13]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+14]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+15])));
        let w02 = nat32To64(nat16To32(nat8To16(arr[i+16]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+17]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+18]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+19]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+20]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+21]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+22]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+23])));
        let w03 = nat32To64(nat16To32(nat8To16(arr[i+24]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+25]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+26]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+27]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+28]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+29]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+30]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+31])));
        let w04 = nat32To64(nat16To32(nat8To16(arr[i+32]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+33]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+34]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+35]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+36]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+37]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+38]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+39])));
        let w05 = nat32To64(nat16To32(nat8To16(arr[i+40]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+41]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+42]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+43]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+44]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+45]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+46]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+47])));
        let w06 = nat32To64(nat16To32(nat8To16(arr[i+48]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+49]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+50]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+51]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+52]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+53]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+54]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+55])));
        let w07 = nat32To64(nat16To32(nat8To16(arr[i+56]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+57]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+58]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+59]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+60]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+61]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+62]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+63])));
        let w08 = nat32To64(nat16To32(nat8To16(arr[i+64]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+65]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+66]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+67]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+68]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+69]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+70]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+71])));
        let w09 = nat32To64(nat16To32(nat8To16(arr[i+72]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+73]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+74]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+75]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+76]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+77]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+78]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+79])));
        let w10 = nat32To64(nat16To32(nat8To16(arr[i+80]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+81]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+82]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+83]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+84]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+85]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+86]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+87])));
        let w11 = nat32To64(nat16To32(nat8To16(arr[i+88]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+89]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+90]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+91]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+92]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+93]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+94]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+95])));
        let w12 = nat32To64(nat16To32(nat8To16(arr[i+96]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+97]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+98]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+99]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+100]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+101]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+102]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+103])));
        let w13 = nat32To64(nat16To32(nat8To16(arr[i+104]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+105]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+106]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+107]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+108]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+109]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+110]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+111])));
        let w14 = nat32To64(nat16To32(nat8To16(arr[i+112]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+113]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+114]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+115]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+116]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+117]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+118]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+119])));
        let w15 = nat32To64(nat16To32(nat8To16(arr[i+120]))) << 56 | nat32To64(nat16To32(nat8To16(arr[i+121]))) << 48 | nat32To64(nat16To32(nat8To16(arr[i+122]))) << 40 | nat32To64(nat16To32(nat8To16(arr[i+123]))) << 32 | nat32To64(nat16To32(nat8To16(arr[i+124]))) << 24 | nat32To64(nat16To32(nat8To16(arr[i+125]))) << 16 | nat32To64(nat16To32(nat8To16(arr[i+126]))) << 8 | nat32To64(nat16To32(nat8To16(arr[i+127])));

        let w16 = w00 +% rot(w01, 01) ^ rot(w01, 08) ^ (w01 >> 07) +% w09 +% rot(w14, 19) ^ rot(w14, 61) ^ (w14 >> 06);
        let w17 = w01 +% rot(w02, 01) ^ rot(w02, 08) ^ (w02 >> 07) +% w10 +% rot(w15, 19) ^ rot(w15, 61) ^ (w15 >> 06);
        let w18 = w02 +% rot(w03, 01) ^ rot(w03, 08) ^ (w03 >> 07) +% w11 +% rot(w16, 19) ^ rot(w16, 61) ^ (w16 >> 06);
        let w19 = w03 +% rot(w04, 01) ^ rot(w04, 08) ^ (w04 >> 07) +% w12 +% rot(w17, 19) ^ rot(w17, 61) ^ (w17 >> 06);
        let w20 = w04 +% rot(w05, 01) ^ rot(w05, 08) ^ (w05 >> 07) +% w13 +% rot(w18, 19) ^ rot(w18, 61) ^ (w18 >> 06);
        let w21 = w05 +% rot(w06, 01) ^ rot(w06, 08) ^ (w06 >> 07) +% w14 +% rot(w19, 19) ^ rot(w19, 61) ^ (w19 >> 06);
        let w22 = w06 +% rot(w07, 01) ^ rot(w07, 08) ^ (w07 >> 07) +% w15 +% rot(w20, 19) ^ rot(w20, 61) ^ (w20 >> 06);
        let w23 = w07 +% rot(w08, 01) ^ rot(w08, 08) ^ (w08 >> 07) +% w16 +% rot(w21, 19) ^ rot(w21, 61) ^ (w21 >> 06);
        let w24 = w08 +% rot(w09, 01) ^ rot(w09, 08) ^ (w09 >> 07) +% w17 +% rot(w22, 19) ^ rot(w22, 61) ^ (w22 >> 06);
        let w25 = w09 +% rot(w10, 01) ^ rot(w10, 08) ^ (w10 >> 07) +% w18 +% rot(w23, 19) ^ rot(w23, 61) ^ (w23 >> 06);
        let w26 = w10 +% rot(w11, 01) ^ rot(w11, 08) ^ (w11 >> 07) +% w19 +% rot(w24, 19) ^ rot(w24, 61) ^ (w24 >> 06);
        let w27 = w11 +% rot(w12, 01) ^ rot(w12, 08) ^ (w12 >> 07) +% w20 +% rot(w25, 19) ^ rot(w25, 61) ^ (w25 >> 06);
        let w28 = w12 +% rot(w13, 01) ^ rot(w13, 08) ^ (w13 >> 07) +% w21 +% rot(w26, 19) ^ rot(w26, 61) ^ (w26 >> 06);
        let w29 = w13 +% rot(w14, 01) ^ rot(w14, 08) ^ (w14 >> 07) +% w22 +% rot(w27, 19) ^ rot(w27, 61) ^ (w27 >> 06);
        let w30 = w14 +% rot(w15, 01) ^ rot(w15, 08) ^ (w15 >> 07) +% w23 +% rot(w28, 19) ^ rot(w28, 61) ^ (w28 >> 06);
        let w31 = w15 +% rot(w16, 01) ^ rot(w16, 08) ^ (w16 >> 07) +% w24 +% rot(w29, 19) ^ rot(w29, 61) ^ (w29 >> 06);
        let w32 = w16 +% rot(w17, 01) ^ rot(w17, 08) ^ (w17 >> 07) +% w25 +% rot(w30, 19) ^ rot(w30, 61) ^ (w30 >> 06);
        let w33 = w17 +% rot(w18, 01) ^ rot(w18, 08) ^ (w18 >> 07) +% w26 +% rot(w31, 19) ^ rot(w31, 61) ^ (w31 >> 06);
        let w34 = w18 +% rot(w19, 01) ^ rot(w19, 08) ^ (w19 >> 07) +% w27 +% rot(w32, 19) ^ rot(w32, 61) ^ (w32 >> 06);
        let w35 = w19 +% rot(w20, 01) ^ rot(w20, 08) ^ (w20 >> 07) +% w28 +% rot(w33, 19) ^ rot(w33, 61) ^ (w33 >> 06);
        let w36 = w20 +% rot(w21, 01) ^ rot(w21, 08) ^ (w21 >> 07) +% w29 +% rot(w34, 19) ^ rot(w34, 61) ^ (w34 >> 06);
        let w37 = w21 +% rot(w22, 01) ^ rot(w22, 08) ^ (w22 >> 07) +% w30 +% rot(w35, 19) ^ rot(w35, 61) ^ (w35 >> 06);
        let w38 = w22 +% rot(w23, 01) ^ rot(w23, 08) ^ (w23 >> 07) +% w31 +% rot(w36, 19) ^ rot(w36, 61) ^ (w36 >> 06);
        let w39 = w23 +% rot(w24, 01) ^ rot(w24, 08) ^ (w24 >> 07) +% w32 +% rot(w37, 19) ^ rot(w37, 61) ^ (w37 >> 06);
        let w40 = w24 +% rot(w25, 01) ^ rot(w25, 08) ^ (w25 >> 07) +% w33 +% rot(w38, 19) ^ rot(w38, 61) ^ (w38 >> 06);
        let w41 = w25 +% rot(w26, 01) ^ rot(w26, 08) ^ (w26 >> 07) +% w34 +% rot(w39, 19) ^ rot(w39, 61) ^ (w39 >> 06);
        let w42 = w26 +% rot(w27, 01) ^ rot(w27, 08) ^ (w27 >> 07) +% w35 +% rot(w40, 19) ^ rot(w40, 61) ^ (w40 >> 06);
        let w43 = w27 +% rot(w28, 01) ^ rot(w28, 08) ^ (w28 >> 07) +% w36 +% rot(w41, 19) ^ rot(w41, 61) ^ (w41 >> 06);
        let w44 = w28 +% rot(w29, 01) ^ rot(w29, 08) ^ (w29 >> 07) +% w37 +% rot(w42, 19) ^ rot(w42, 61) ^ (w42 >> 06);
        let w45 = w29 +% rot(w30, 01) ^ rot(w30, 08) ^ (w30 >> 07) +% w38 +% rot(w43, 19) ^ rot(w43, 61) ^ (w43 >> 06);
        let w46 = w30 +% rot(w31, 01) ^ rot(w31, 08) ^ (w31 >> 07) +% w39 +% rot(w44, 19) ^ rot(w44, 61) ^ (w44 >> 06);
        let w47 = w31 +% rot(w32, 01) ^ rot(w32, 08) ^ (w32 >> 07) +% w40 +% rot(w45, 19) ^ rot(w45, 61) ^ (w45 >> 06);
        let w48 = w32 +% rot(w33, 01) ^ rot(w33, 08) ^ (w33 >> 07) +% w41 +% rot(w46, 19) ^ rot(w46, 61) ^ (w46 >> 06);
        let w49 = w33 +% rot(w34, 01) ^ rot(w34, 08) ^ (w34 >> 07) +% w42 +% rot(w47, 19) ^ rot(w47, 61) ^ (w47 >> 06);
        let w50 = w34 +% rot(w35, 01) ^ rot(w35, 08) ^ (w35 >> 07) +% w43 +% rot(w48, 19) ^ rot(w48, 61) ^ (w48 >> 06);
        let w51 = w35 +% rot(w36, 01) ^ rot(w36, 08) ^ (w36 >> 07) +% w44 +% rot(w49, 19) ^ rot(w49, 61) ^ (w49 >> 06);
        let w52 = w36 +% rot(w37, 01) ^ rot(w37, 08) ^ (w37 >> 07) +% w45 +% rot(w50, 19) ^ rot(w50, 61) ^ (w50 >> 06);
        let w53 = w37 +% rot(w38, 01) ^ rot(w38, 08) ^ (w38 >> 07) +% w46 +% rot(w51, 19) ^ rot(w51, 61) ^ (w51 >> 06);
        let w54 = w38 +% rot(w39, 01) ^ rot(w39, 08) ^ (w39 >> 07) +% w47 +% rot(w52, 19) ^ rot(w52, 61) ^ (w52 >> 06);
        let w55 = w39 +% rot(w40, 01) ^ rot(w40, 08) ^ (w40 >> 07) +% w48 +% rot(w53, 19) ^ rot(w53, 61) ^ (w53 >> 06);
        let w56 = w40 +% rot(w41, 01) ^ rot(w41, 08) ^ (w41 >> 07) +% w49 +% rot(w54, 19) ^ rot(w54, 61) ^ (w54 >> 06);
        let w57 = w41 +% rot(w42, 01) ^ rot(w42, 08) ^ (w42 >> 07) +% w50 +% rot(w55, 19) ^ rot(w55, 61) ^ (w55 >> 06);
        let w58 = w42 +% rot(w43, 01) ^ rot(w43, 08) ^ (w43 >> 07) +% w51 +% rot(w56, 19) ^ rot(w56, 61) ^ (w56 >> 06);
        let w59 = w43 +% rot(w44, 01) ^ rot(w44, 08) ^ (w44 >> 07) +% w52 +% rot(w57, 19) ^ rot(w57, 61) ^ (w57 >> 06);
        let w60 = w44 +% rot(w45, 01) ^ rot(w45, 08) ^ (w45 >> 07) +% w53 +% rot(w58, 19) ^ rot(w58, 61) ^ (w58 >> 06);
        let w61 = w45 +% rot(w46, 01) ^ rot(w46, 08) ^ (w46 >> 07) +% w54 +% rot(w59, 19) ^ rot(w59, 61) ^ (w59 >> 06);
        let w62 = w46 +% rot(w47, 01) ^ rot(w47, 08) ^ (w47 >> 07) +% w55 +% rot(w60, 19) ^ rot(w60, 61) ^ (w60 >> 06);
        let w63 = w47 +% rot(w48, 01) ^ rot(w48, 08) ^ (w48 >> 07) +% w56 +% rot(w61, 19) ^ rot(w61, 61) ^ (w61 >> 06);
        let w64 = w48 +% rot(w49, 01) ^ rot(w49, 08) ^ (w49 >> 07) +% w57 +% rot(w62, 19) ^ rot(w62, 61) ^ (w62 >> 06);
        let w65 = w49 +% rot(w50, 01) ^ rot(w50, 08) ^ (w50 >> 07) +% w58 +% rot(w63, 19) ^ rot(w63, 61) ^ (w63 >> 06);
        let w66 = w50 +% rot(w51, 01) ^ rot(w51, 08) ^ (w51 >> 07) +% w59 +% rot(w64, 19) ^ rot(w64, 61) ^ (w64 >> 06);
        let w67 = w51 +% rot(w52, 01) ^ rot(w52, 08) ^ (w52 >> 07) +% w60 +% rot(w65, 19) ^ rot(w65, 61) ^ (w65 >> 06);
        let w68 = w52 +% rot(w53, 01) ^ rot(w53, 08) ^ (w53 >> 07) +% w61 +% rot(w66, 19) ^ rot(w66, 61) ^ (w66 >> 06);
        let w69 = w53 +% rot(w54, 01) ^ rot(w54, 08) ^ (w54 >> 07) +% w62 +% rot(w67, 19) ^ rot(w67, 61) ^ (w67 >> 06);
        let w70 = w54 +% rot(w55, 01) ^ rot(w55, 08) ^ (w55 >> 07) +% w63 +% rot(w68, 19) ^ rot(w68, 61) ^ (w68 >> 06);
        let w71 = w55 +% rot(w56, 01) ^ rot(w56, 08) ^ (w56 >> 07) +% w64 +% rot(w69, 19) ^ rot(w69, 61) ^ (w69 >> 06);
        let w72 = w56 +% rot(w57, 01) ^ rot(w57, 08) ^ (w57 >> 07) +% w65 +% rot(w70, 19) ^ rot(w70, 61) ^ (w70 >> 06);
        let w73 = w57 +% rot(w58, 01) ^ rot(w58, 08) ^ (w58 >> 07) +% w66 +% rot(w71, 19) ^ rot(w71, 61) ^ (w71 >> 06);
        let w74 = w58 +% rot(w59, 01) ^ rot(w59, 08) ^ (w59 >> 07) +% w67 +% rot(w72, 19) ^ rot(w72, 61) ^ (w72 >> 06);
        let w75 = w59 +% rot(w60, 01) ^ rot(w60, 08) ^ (w60 >> 07) +% w68 +% rot(w73, 19) ^ rot(w73, 61) ^ (w73 >> 06);
        let w76 = w60 +% rot(w61, 01) ^ rot(w61, 08) ^ (w61 >> 07) +% w69 +% rot(w74, 19) ^ rot(w74, 61) ^ (w74 >> 06);
        let w77 = w61 +% rot(w62, 01) ^ rot(w62, 08) ^ (w62 >> 07) +% w70 +% rot(w75, 19) ^ rot(w75, 61) ^ (w75 >> 06);
        let w78 = w62 +% rot(w63, 01) ^ rot(w63, 08) ^ (w63 >> 07) +% w71 +% rot(w76, 19) ^ rot(w76, 61) ^ (w76 >> 06);
        let w79 = w63 +% rot(w64, 01) ^ rot(w64, 08) ^ (w64 >> 07) +% w72 +% rot(w77, 19) ^ rot(w77, 61) ^ (w77 >> 06);

        t := h +% K00 +% w00 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K01 +% w01 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K02 +% w02 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K03 +% w03 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K04 +% w04 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K05 +% w05 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K06 +% w06 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K07 +% w07 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K08 +% w08 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K09 +% w09 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K10 +% w10 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K11 +% w11 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K12 +% w12 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K13 +% w13 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K14 +% w14 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K15 +% w15 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K16 +% w16 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K17 +% w17 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K18 +% w18 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K19 +% w19 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K20 +% w20 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K21 +% w21 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K22 +% w22 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K23 +% w23 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K24 +% w24 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K25 +% w25 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K26 +% w26 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K27 +% w27 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K28 +% w28 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K29 +% w29 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K30 +% w30 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K31 +% w31 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K32 +% w32 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K33 +% w33 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K34 +% w34 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K35 +% w35 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K36 +% w36 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K37 +% w37 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K38 +% w38 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K39 +% w39 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K40 +% w40 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K41 +% w41 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K42 +% w42 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K43 +% w43 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K44 +% w44 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K45 +% w45 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K46 +% w46 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K47 +% w47 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K48 +% w48 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K49 +% w49 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K50 +% w50 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K51 +% w51 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K52 +% w52 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K53 +% w53 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K54 +% w54 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K55 +% w55 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K56 +% w56 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K57 +% w57 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K58 +% w58 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K59 +% w59 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K60 +% w60 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K61 +% w61 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K62 +% w62 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K63 +% w63 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K64 +% w64 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K65 +% w65 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K66 +% w66 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K67 +% w67 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K68 +% w68 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K69 +% w69 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K70 +% w70 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K71 +% w71 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K72 +% w72 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K73 +% w73 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K74 +% w74 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K75 +% w75 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K76 +% w76 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K77 +% w77 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K78 +% w78 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
        t := h +% K79 +% w79 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);

        // final addition
        a +%= a_0;
        b +%= b_0;
        c +%= c_0;
        d +%= d_0;
        e +%= e_0;
        f +%= f_0;
        g +%= g_0;
        h +%= h_0;

        // counters
        i += 128;
        i_block +%= 1;
      };
      // write state back to registers
      s0 := a;
      s1 := b;
      s2 := c;
      s3 := d;
      s4 := e;
      s5 := f;
      s6 := g;
      s7 := h;

      return i
    };

    private func process_blocks_from_iter(data : () -> ?Nat8) {
      // load state registers
      var a = s0;
      var b = s1;
      var c = s2;
      var d = s3;
      var e = s4;
      var f = s5;
      var g = s6;
      var h = s7;
      var t = 0 : Nat64;

      let backup = VarArray.repeat<Nat8>(0, 128);
      var pos = 0;
      ignore do ? {
        loop {

          let b000 = data()!; backup[0] := b000; pos := 1;
          let b001 = data()!; backup[1] := b001; pos := 2;
          let b002 = data()!; backup[2] := b002; pos := 3;
          let b003 = data()!; backup[3] := b003; pos := 4;
          let b004 = data()!; backup[4] := b004; pos := 5;
          let b005 = data()!; backup[5] := b005; pos := 6;
          let b006 = data()!; backup[6] := b006; pos := 7;
          let b007 = data()!; backup[7] := b007; pos := 8;
          let b008 = data()!; backup[8] := b008; pos := 9;
          let b009 = data()!; backup[9] := b009; pos := 10;
          let b010 = data()!; backup[10] := b010; pos := 11;
          let b011 = data()!; backup[11] := b011; pos := 12;
          let b012 = data()!; backup[12] := b012; pos := 13;
          let b013 = data()!; backup[13] := b013; pos := 14;
          let b014 = data()!; backup[14] := b014; pos := 15;
          let b015 = data()!; backup[15] := b015; pos := 16;
          let b016 = data()!; backup[16] := b016; pos := 17;
          let b017 = data()!; backup[17] := b017; pos := 18;
          let b018 = data()!; backup[18] := b018; pos := 19;
          let b019 = data()!; backup[19] := b019; pos := 20;
          let b020 = data()!; backup[20] := b020; pos := 21;
          let b021 = data()!; backup[21] := b021; pos := 22;
          let b022 = data()!; backup[22] := b022; pos := 23;
          let b023 = data()!; backup[23] := b023; pos := 24;
          let b024 = data()!; backup[24] := b024; pos := 25;
          let b025 = data()!; backup[25] := b025; pos := 26;
          let b026 = data()!; backup[26] := b026; pos := 27;
          let b027 = data()!; backup[27] := b027; pos := 28;
          let b028 = data()!; backup[28] := b028; pos := 29;
          let b029 = data()!; backup[29] := b029; pos := 30;
          let b030 = data()!; backup[30] := b030; pos := 31;
          let b031 = data()!; backup[31] := b031; pos := 32;
          let b032 = data()!; backup[32] := b032; pos := 33;
          let b033 = data()!; backup[33] := b033; pos := 34;
          let b034 = data()!; backup[34] := b034; pos := 35;
          let b035 = data()!; backup[35] := b035; pos := 36;
          let b036 = data()!; backup[36] := b036; pos := 37;
          let b037 = data()!; backup[37] := b037; pos := 38;
          let b038 = data()!; backup[38] := b038; pos := 39;
          let b039 = data()!; backup[39] := b039; pos := 40;
          let b040 = data()!; backup[40] := b040; pos := 41;
          let b041 = data()!; backup[41] := b041; pos := 42;
          let b042 = data()!; backup[42] := b042; pos := 43;
          let b043 = data()!; backup[43] := b043; pos := 44;
          let b044 = data()!; backup[44] := b044; pos := 45;
          let b045 = data()!; backup[45] := b045; pos := 46;
          let b046 = data()!; backup[46] := b046; pos := 47;
          let b047 = data()!; backup[47] := b047; pos := 48;
          let b048 = data()!; backup[48] := b048; pos := 49;
          let b049 = data()!; backup[49] := b049; pos := 50;
          let b050 = data()!; backup[50] := b050; pos := 51;
          let b051 = data()!; backup[51] := b051; pos := 52;
          let b052 = data()!; backup[52] := b052; pos := 53;
          let b053 = data()!; backup[53] := b053; pos := 54;
          let b054 = data()!; backup[54] := b054; pos := 55;
          let b055 = data()!; backup[55] := b055; pos := 56;
          let b056 = data()!; backup[56] := b056; pos := 57;
          let b057 = data()!; backup[57] := b057; pos := 58;
          let b058 = data()!; backup[58] := b058; pos := 59;
          let b059 = data()!; backup[59] := b059; pos := 60;
          let b060 = data()!; backup[60] := b060; pos := 61;
          let b061 = data()!; backup[61] := b061; pos := 62;
          let b062 = data()!; backup[62] := b062; pos := 63;
          let b063 = data()!; backup[63] := b063; pos := 64;
          let b064 = data()!; backup[64] := b064; pos := 65;
          let b065 = data()!; backup[65] := b065; pos := 66;
          let b066 = data()!; backup[66] := b066; pos := 67;
          let b067 = data()!; backup[67] := b067; pos := 68;
          let b068 = data()!; backup[68] := b068; pos := 69;
          let b069 = data()!; backup[69] := b069; pos := 70;
          let b070 = data()!; backup[70] := b070; pos := 71;
          let b071 = data()!; backup[71] := b071; pos := 72;
          let b072 = data()!; backup[72] := b072; pos := 73;
          let b073 = data()!; backup[73] := b073; pos := 74;
          let b074 = data()!; backup[74] := b074; pos := 75;
          let b075 = data()!; backup[75] := b075; pos := 76;
          let b076 = data()!; backup[76] := b076; pos := 77;
          let b077 = data()!; backup[77] := b077; pos := 78;
          let b078 = data()!; backup[78] := b078; pos := 79;
          let b079 = data()!; backup[79] := b079; pos := 80;
          let b080 = data()!; backup[80] := b080; pos := 81;
          let b081 = data()!; backup[81] := b081; pos := 82;
          let b082 = data()!; backup[82] := b082; pos := 83;
          let b083 = data()!; backup[83] := b083; pos := 84;
          let b084 = data()!; backup[84] := b084; pos := 85;
          let b085 = data()!; backup[85] := b085; pos := 86;
          let b086 = data()!; backup[86] := b086; pos := 87;
          let b087 = data()!; backup[87] := b087; pos := 88;
          let b088 = data()!; backup[88] := b088; pos := 89;
          let b089 = data()!; backup[89] := b089; pos := 90;
          let b090 = data()!; backup[90] := b090; pos := 91;
          let b091 = data()!; backup[91] := b091; pos := 92;
          let b092 = data()!; backup[92] := b092; pos := 93;
          let b093 = data()!; backup[93] := b093; pos := 94;
          let b094 = data()!; backup[94] := b094; pos := 95;
          let b095 = data()!; backup[95] := b095; pos := 96;
          let b096 = data()!; backup[96] := b096; pos := 97;
          let b097 = data()!; backup[97] := b097; pos := 98;
          let b098 = data()!; backup[98] := b098; pos := 99;
          let b099 = data()!; backup[99] := b099; pos := 100;
          let b100 = data()!; backup[100] := b100; pos := 101;
          let b101 = data()!; backup[101] := b101; pos := 102;
          let b102 = data()!; backup[102] := b102; pos := 103;
          let b103 = data()!; backup[103] := b103; pos := 104;
          let b104 = data()!; backup[104] := b104; pos := 105;
          let b105 = data()!; backup[105] := b105; pos := 106;
          let b106 = data()!; backup[106] := b106; pos := 107;
          let b107 = data()!; backup[107] := b107; pos := 108;
          let b108 = data()!; backup[108] := b108; pos := 109;
          let b109 = data()!; backup[109] := b109; pos := 110;
          let b110 = data()!; backup[110] := b110; pos := 111;
          let b111 = data()!; backup[111] := b111; pos := 112;
          let b112 = data()!; backup[112] := b112; pos := 113;
          let b113 = data()!; backup[113] := b113; pos := 114;
          let b114 = data()!; backup[114] := b114; pos := 115;
          let b115 = data()!; backup[115] := b115; pos := 116;
          let b116 = data()!; backup[116] := b116; pos := 117;
          let b117 = data()!; backup[117] := b117; pos := 118;
          let b118 = data()!; backup[118] := b118; pos := 119;
          let b119 = data()!; backup[119] := b119; pos := 120;
          let b120 = data()!; backup[120] := b120; pos := 121;
          let b121 = data()!; backup[121] := b121; pos := 122;
          let b122 = data()!; backup[122] := b122; pos := 123;
          let b123 = data()!; backup[123] := b123; pos := 124;
          let b124 = data()!; backup[124] := b124; pos := 125;
          let b125 = data()!; backup[125] := b125; pos := 126;
          let b126 = data()!; backup[126] := b126; pos := 127;
          let b127 = data()!; backup[127] := b127; pos := 0;

          let a_0 = a;
          let b_0 = b;
          let c_0 = c;
          let d_0 = d;
          let e_0 = e;
          let f_0 = f;
          let g_0 = g;
          let h_0 = h;

          let w00 = nat32To64(nat16To32(nat8To16(b000))) << 56 | nat32To64(nat16To32(nat8To16(b001))) << 48 | nat32To64(nat16To32(nat8To16(b002))) << 40 | nat32To64(nat16To32(nat8To16(b003))) << 32 | nat32To64(nat16To32(nat8To16(b004))) << 24 | nat32To64(nat16To32(nat8To16(b005))) << 16 | nat32To64(nat16To32(nat8To16(b006))) << 8 | nat32To64(nat16To32(nat8To16(b007)));
          let w01 = nat32To64(nat16To32(nat8To16(b008))) << 56 | nat32To64(nat16To32(nat8To16(b009))) << 48 | nat32To64(nat16To32(nat8To16(b010))) << 40 | nat32To64(nat16To32(nat8To16(b011))) << 32 | nat32To64(nat16To32(nat8To16(b012))) << 24 | nat32To64(nat16To32(nat8To16(b013))) << 16 | nat32To64(nat16To32(nat8To16(b014))) << 8 | nat32To64(nat16To32(nat8To16(b015)));
          let w02 = nat32To64(nat16To32(nat8To16(b016))) << 56 | nat32To64(nat16To32(nat8To16(b017))) << 48 | nat32To64(nat16To32(nat8To16(b018))) << 40 | nat32To64(nat16To32(nat8To16(b019))) << 32 | nat32To64(nat16To32(nat8To16(b020))) << 24 | nat32To64(nat16To32(nat8To16(b021))) << 16 | nat32To64(nat16To32(nat8To16(b022))) << 8 | nat32To64(nat16To32(nat8To16(b023)));
          let w03 = nat32To64(nat16To32(nat8To16(b024))) << 56 | nat32To64(nat16To32(nat8To16(b025))) << 48 | nat32To64(nat16To32(nat8To16(b026))) << 40 | nat32To64(nat16To32(nat8To16(b027))) << 32 | nat32To64(nat16To32(nat8To16(b028))) << 24 | nat32To64(nat16To32(nat8To16(b029))) << 16 | nat32To64(nat16To32(nat8To16(b030))) << 8 | nat32To64(nat16To32(nat8To16(b031)));
          let w04 = nat32To64(nat16To32(nat8To16(b032))) << 56 | nat32To64(nat16To32(nat8To16(b033))) << 48 | nat32To64(nat16To32(nat8To16(b034))) << 40 | nat32To64(nat16To32(nat8To16(b035))) << 32 | nat32To64(nat16To32(nat8To16(b036))) << 24 | nat32To64(nat16To32(nat8To16(b037))) << 16 | nat32To64(nat16To32(nat8To16(b038))) << 8 | nat32To64(nat16To32(nat8To16(b039)));
          let w05 = nat32To64(nat16To32(nat8To16(b040))) << 56 | nat32To64(nat16To32(nat8To16(b041))) << 48 | nat32To64(nat16To32(nat8To16(b042))) << 40 | nat32To64(nat16To32(nat8To16(b043))) << 32 | nat32To64(nat16To32(nat8To16(b044))) << 24 | nat32To64(nat16To32(nat8To16(b045))) << 16 | nat32To64(nat16To32(nat8To16(b046))) << 8 | nat32To64(nat16To32(nat8To16(b047)));
          let w06 = nat32To64(nat16To32(nat8To16(b048))) << 56 | nat32To64(nat16To32(nat8To16(b049))) << 48 | nat32To64(nat16To32(nat8To16(b050))) << 40 | nat32To64(nat16To32(nat8To16(b051))) << 32 | nat32To64(nat16To32(nat8To16(b052))) << 24 | nat32To64(nat16To32(nat8To16(b053))) << 16 | nat32To64(nat16To32(nat8To16(b054))) << 8 | nat32To64(nat16To32(nat8To16(b055)));
          let w07 = nat32To64(nat16To32(nat8To16(b056))) << 56 | nat32To64(nat16To32(nat8To16(b057))) << 48 | nat32To64(nat16To32(nat8To16(b058))) << 40 | nat32To64(nat16To32(nat8To16(b059))) << 32 | nat32To64(nat16To32(nat8To16(b060))) << 24 | nat32To64(nat16To32(nat8To16(b061))) << 16 | nat32To64(nat16To32(nat8To16(b062))) << 8 | nat32To64(nat16To32(nat8To16(b063)));
          let w08 = nat32To64(nat16To32(nat8To16(b064))) << 56 | nat32To64(nat16To32(nat8To16(b065))) << 48 | nat32To64(nat16To32(nat8To16(b066))) << 40 | nat32To64(nat16To32(nat8To16(b067))) << 32 | nat32To64(nat16To32(nat8To16(b068))) << 24 | nat32To64(nat16To32(nat8To16(b069))) << 16 | nat32To64(nat16To32(nat8To16(b070))) << 8 | nat32To64(nat16To32(nat8To16(b071)));
          let w09 = nat32To64(nat16To32(nat8To16(b072))) << 56 | nat32To64(nat16To32(nat8To16(b073))) << 48 | nat32To64(nat16To32(nat8To16(b074))) << 40 | nat32To64(nat16To32(nat8To16(b075))) << 32 | nat32To64(nat16To32(nat8To16(b076))) << 24 | nat32To64(nat16To32(nat8To16(b077))) << 16 | nat32To64(nat16To32(nat8To16(b078))) << 8 | nat32To64(nat16To32(nat8To16(b079)));
          let w10 = nat32To64(nat16To32(nat8To16(b080))) << 56 | nat32To64(nat16To32(nat8To16(b081))) << 48 | nat32To64(nat16To32(nat8To16(b082))) << 40 | nat32To64(nat16To32(nat8To16(b083))) << 32 | nat32To64(nat16To32(nat8To16(b084))) << 24 | nat32To64(nat16To32(nat8To16(b085))) << 16 | nat32To64(nat16To32(nat8To16(b086))) << 8 | nat32To64(nat16To32(nat8To16(b087)));
          let w11 = nat32To64(nat16To32(nat8To16(b088))) << 56 | nat32To64(nat16To32(nat8To16(b089))) << 48 | nat32To64(nat16To32(nat8To16(b090))) << 40 | nat32To64(nat16To32(nat8To16(b091))) << 32 | nat32To64(nat16To32(nat8To16(b092))) << 24 | nat32To64(nat16To32(nat8To16(b093))) << 16 | nat32To64(nat16To32(nat8To16(b094))) << 8 | nat32To64(nat16To32(nat8To16(b095)));
          let w12 = nat32To64(nat16To32(nat8To16(b096))) << 56 | nat32To64(nat16To32(nat8To16(b097))) << 48 | nat32To64(nat16To32(nat8To16(b098))) << 40 | nat32To64(nat16To32(nat8To16(b099))) << 32 | nat32To64(nat16To32(nat8To16(b100))) << 24 | nat32To64(nat16To32(nat8To16(b101))) << 16 | nat32To64(nat16To32(nat8To16(b102))) << 8 | nat32To64(nat16To32(nat8To16(b103)));
          let w13 = nat32To64(nat16To32(nat8To16(b104))) << 56 | nat32To64(nat16To32(nat8To16(b105))) << 48 | nat32To64(nat16To32(nat8To16(b106))) << 40 | nat32To64(nat16To32(nat8To16(b107))) << 32 | nat32To64(nat16To32(nat8To16(b108))) << 24 | nat32To64(nat16To32(nat8To16(b109))) << 16 | nat32To64(nat16To32(nat8To16(b110))) << 8 | nat32To64(nat16To32(nat8To16(b111)));
          let w14 = nat32To64(nat16To32(nat8To16(b112))) << 56 | nat32To64(nat16To32(nat8To16(b113))) << 48 | nat32To64(nat16To32(nat8To16(b114))) << 40 | nat32To64(nat16To32(nat8To16(b115))) << 32 | nat32To64(nat16To32(nat8To16(b116))) << 24 | nat32To64(nat16To32(nat8To16(b117))) << 16 | nat32To64(nat16To32(nat8To16(b118))) << 8 | nat32To64(nat16To32(nat8To16(b119)));
          let w15 = nat32To64(nat16To32(nat8To16(b120))) << 56 | nat32To64(nat16To32(nat8To16(b121))) << 48 | nat32To64(nat16To32(nat8To16(b122))) << 40 | nat32To64(nat16To32(nat8To16(b123))) << 32 | nat32To64(nat16To32(nat8To16(b124))) << 24 | nat32To64(nat16To32(nat8To16(b125))) << 16 | nat32To64(nat16To32(nat8To16(b126))) << 8 | nat32To64(nat16To32(nat8To16(b127)));

          let w16 = w00 +% rot(w01, 01) ^ rot(w01, 08) ^ (w01 >> 07) +% w09 +% rot(w14, 19) ^ rot(w14, 61) ^ (w14 >> 06);
          let w17 = w01 +% rot(w02, 01) ^ rot(w02, 08) ^ (w02 >> 07) +% w10 +% rot(w15, 19) ^ rot(w15, 61) ^ (w15 >> 06);
          let w18 = w02 +% rot(w03, 01) ^ rot(w03, 08) ^ (w03 >> 07) +% w11 +% rot(w16, 19) ^ rot(w16, 61) ^ (w16 >> 06);
          let w19 = w03 +% rot(w04, 01) ^ rot(w04, 08) ^ (w04 >> 07) +% w12 +% rot(w17, 19) ^ rot(w17, 61) ^ (w17 >> 06);
          let w20 = w04 +% rot(w05, 01) ^ rot(w05, 08) ^ (w05 >> 07) +% w13 +% rot(w18, 19) ^ rot(w18, 61) ^ (w18 >> 06);
          let w21 = w05 +% rot(w06, 01) ^ rot(w06, 08) ^ (w06 >> 07) +% w14 +% rot(w19, 19) ^ rot(w19, 61) ^ (w19 >> 06);
          let w22 = w06 +% rot(w07, 01) ^ rot(w07, 08) ^ (w07 >> 07) +% w15 +% rot(w20, 19) ^ rot(w20, 61) ^ (w20 >> 06);
          let w23 = w07 +% rot(w08, 01) ^ rot(w08, 08) ^ (w08 >> 07) +% w16 +% rot(w21, 19) ^ rot(w21, 61) ^ (w21 >> 06);
          let w24 = w08 +% rot(w09, 01) ^ rot(w09, 08) ^ (w09 >> 07) +% w17 +% rot(w22, 19) ^ rot(w22, 61) ^ (w22 >> 06);
          let w25 = w09 +% rot(w10, 01) ^ rot(w10, 08) ^ (w10 >> 07) +% w18 +% rot(w23, 19) ^ rot(w23, 61) ^ (w23 >> 06);
          let w26 = w10 +% rot(w11, 01) ^ rot(w11, 08) ^ (w11 >> 07) +% w19 +% rot(w24, 19) ^ rot(w24, 61) ^ (w24 >> 06);
          let w27 = w11 +% rot(w12, 01) ^ rot(w12, 08) ^ (w12 >> 07) +% w20 +% rot(w25, 19) ^ rot(w25, 61) ^ (w25 >> 06);
          let w28 = w12 +% rot(w13, 01) ^ rot(w13, 08) ^ (w13 >> 07) +% w21 +% rot(w26, 19) ^ rot(w26, 61) ^ (w26 >> 06);
          let w29 = w13 +% rot(w14, 01) ^ rot(w14, 08) ^ (w14 >> 07) +% w22 +% rot(w27, 19) ^ rot(w27, 61) ^ (w27 >> 06);
          let w30 = w14 +% rot(w15, 01) ^ rot(w15, 08) ^ (w15 >> 07) +% w23 +% rot(w28, 19) ^ rot(w28, 61) ^ (w28 >> 06);
          let w31 = w15 +% rot(w16, 01) ^ rot(w16, 08) ^ (w16 >> 07) +% w24 +% rot(w29, 19) ^ rot(w29, 61) ^ (w29 >> 06);
          let w32 = w16 +% rot(w17, 01) ^ rot(w17, 08) ^ (w17 >> 07) +% w25 +% rot(w30, 19) ^ rot(w30, 61) ^ (w30 >> 06);
          let w33 = w17 +% rot(w18, 01) ^ rot(w18, 08) ^ (w18 >> 07) +% w26 +% rot(w31, 19) ^ rot(w31, 61) ^ (w31 >> 06);
          let w34 = w18 +% rot(w19, 01) ^ rot(w19, 08) ^ (w19 >> 07) +% w27 +% rot(w32, 19) ^ rot(w32, 61) ^ (w32 >> 06);
          let w35 = w19 +% rot(w20, 01) ^ rot(w20, 08) ^ (w20 >> 07) +% w28 +% rot(w33, 19) ^ rot(w33, 61) ^ (w33 >> 06);
          let w36 = w20 +% rot(w21, 01) ^ rot(w21, 08) ^ (w21 >> 07) +% w29 +% rot(w34, 19) ^ rot(w34, 61) ^ (w34 >> 06);
          let w37 = w21 +% rot(w22, 01) ^ rot(w22, 08) ^ (w22 >> 07) +% w30 +% rot(w35, 19) ^ rot(w35, 61) ^ (w35 >> 06);
          let w38 = w22 +% rot(w23, 01) ^ rot(w23, 08) ^ (w23 >> 07) +% w31 +% rot(w36, 19) ^ rot(w36, 61) ^ (w36 >> 06);
          let w39 = w23 +% rot(w24, 01) ^ rot(w24, 08) ^ (w24 >> 07) +% w32 +% rot(w37, 19) ^ rot(w37, 61) ^ (w37 >> 06);
          let w40 = w24 +% rot(w25, 01) ^ rot(w25, 08) ^ (w25 >> 07) +% w33 +% rot(w38, 19) ^ rot(w38, 61) ^ (w38 >> 06);
          let w41 = w25 +% rot(w26, 01) ^ rot(w26, 08) ^ (w26 >> 07) +% w34 +% rot(w39, 19) ^ rot(w39, 61) ^ (w39 >> 06);
          let w42 = w26 +% rot(w27, 01) ^ rot(w27, 08) ^ (w27 >> 07) +% w35 +% rot(w40, 19) ^ rot(w40, 61) ^ (w40 >> 06);
          let w43 = w27 +% rot(w28, 01) ^ rot(w28, 08) ^ (w28 >> 07) +% w36 +% rot(w41, 19) ^ rot(w41, 61) ^ (w41 >> 06);
          let w44 = w28 +% rot(w29, 01) ^ rot(w29, 08) ^ (w29 >> 07) +% w37 +% rot(w42, 19) ^ rot(w42, 61) ^ (w42 >> 06);
          let w45 = w29 +% rot(w30, 01) ^ rot(w30, 08) ^ (w30 >> 07) +% w38 +% rot(w43, 19) ^ rot(w43, 61) ^ (w43 >> 06);
          let w46 = w30 +% rot(w31, 01) ^ rot(w31, 08) ^ (w31 >> 07) +% w39 +% rot(w44, 19) ^ rot(w44, 61) ^ (w44 >> 06);
          let w47 = w31 +% rot(w32, 01) ^ rot(w32, 08) ^ (w32 >> 07) +% w40 +% rot(w45, 19) ^ rot(w45, 61) ^ (w45 >> 06);
          let w48 = w32 +% rot(w33, 01) ^ rot(w33, 08) ^ (w33 >> 07) +% w41 +% rot(w46, 19) ^ rot(w46, 61) ^ (w46 >> 06);
          let w49 = w33 +% rot(w34, 01) ^ rot(w34, 08) ^ (w34 >> 07) +% w42 +% rot(w47, 19) ^ rot(w47, 61) ^ (w47 >> 06);
          let w50 = w34 +% rot(w35, 01) ^ rot(w35, 08) ^ (w35 >> 07) +% w43 +% rot(w48, 19) ^ rot(w48, 61) ^ (w48 >> 06);
          let w51 = w35 +% rot(w36, 01) ^ rot(w36, 08) ^ (w36 >> 07) +% w44 +% rot(w49, 19) ^ rot(w49, 61) ^ (w49 >> 06);
          let w52 = w36 +% rot(w37, 01) ^ rot(w37, 08) ^ (w37 >> 07) +% w45 +% rot(w50, 19) ^ rot(w50, 61) ^ (w50 >> 06);
          let w53 = w37 +% rot(w38, 01) ^ rot(w38, 08) ^ (w38 >> 07) +% w46 +% rot(w51, 19) ^ rot(w51, 61) ^ (w51 >> 06);
          let w54 = w38 +% rot(w39, 01) ^ rot(w39, 08) ^ (w39 >> 07) +% w47 +% rot(w52, 19) ^ rot(w52, 61) ^ (w52 >> 06);
          let w55 = w39 +% rot(w40, 01) ^ rot(w40, 08) ^ (w40 >> 07) +% w48 +% rot(w53, 19) ^ rot(w53, 61) ^ (w53 >> 06);
          let w56 = w40 +% rot(w41, 01) ^ rot(w41, 08) ^ (w41 >> 07) +% w49 +% rot(w54, 19) ^ rot(w54, 61) ^ (w54 >> 06);
          let w57 = w41 +% rot(w42, 01) ^ rot(w42, 08) ^ (w42 >> 07) +% w50 +% rot(w55, 19) ^ rot(w55, 61) ^ (w55 >> 06);
          let w58 = w42 +% rot(w43, 01) ^ rot(w43, 08) ^ (w43 >> 07) +% w51 +% rot(w56, 19) ^ rot(w56, 61) ^ (w56 >> 06);
          let w59 = w43 +% rot(w44, 01) ^ rot(w44, 08) ^ (w44 >> 07) +% w52 +% rot(w57, 19) ^ rot(w57, 61) ^ (w57 >> 06);
          let w60 = w44 +% rot(w45, 01) ^ rot(w45, 08) ^ (w45 >> 07) +% w53 +% rot(w58, 19) ^ rot(w58, 61) ^ (w58 >> 06);
          let w61 = w45 +% rot(w46, 01) ^ rot(w46, 08) ^ (w46 >> 07) +% w54 +% rot(w59, 19) ^ rot(w59, 61) ^ (w59 >> 06);
          let w62 = w46 +% rot(w47, 01) ^ rot(w47, 08) ^ (w47 >> 07) +% w55 +% rot(w60, 19) ^ rot(w60, 61) ^ (w60 >> 06);
          let w63 = w47 +% rot(w48, 01) ^ rot(w48, 08) ^ (w48 >> 07) +% w56 +% rot(w61, 19) ^ rot(w61, 61) ^ (w61 >> 06);
          let w64 = w48 +% rot(w49, 01) ^ rot(w49, 08) ^ (w49 >> 07) +% w57 +% rot(w62, 19) ^ rot(w62, 61) ^ (w62 >> 06);
          let w65 = w49 +% rot(w50, 01) ^ rot(w50, 08) ^ (w50 >> 07) +% w58 +% rot(w63, 19) ^ rot(w63, 61) ^ (w63 >> 06);
          let w66 = w50 +% rot(w51, 01) ^ rot(w51, 08) ^ (w51 >> 07) +% w59 +% rot(w64, 19) ^ rot(w64, 61) ^ (w64 >> 06);
          let w67 = w51 +% rot(w52, 01) ^ rot(w52, 08) ^ (w52 >> 07) +% w60 +% rot(w65, 19) ^ rot(w65, 61) ^ (w65 >> 06);
          let w68 = w52 +% rot(w53, 01) ^ rot(w53, 08) ^ (w53 >> 07) +% w61 +% rot(w66, 19) ^ rot(w66, 61) ^ (w66 >> 06);
          let w69 = w53 +% rot(w54, 01) ^ rot(w54, 08) ^ (w54 >> 07) +% w62 +% rot(w67, 19) ^ rot(w67, 61) ^ (w67 >> 06);
          let w70 = w54 +% rot(w55, 01) ^ rot(w55, 08) ^ (w55 >> 07) +% w63 +% rot(w68, 19) ^ rot(w68, 61) ^ (w68 >> 06);
          let w71 = w55 +% rot(w56, 01) ^ rot(w56, 08) ^ (w56 >> 07) +% w64 +% rot(w69, 19) ^ rot(w69, 61) ^ (w69 >> 06);
          let w72 = w56 +% rot(w57, 01) ^ rot(w57, 08) ^ (w57 >> 07) +% w65 +% rot(w70, 19) ^ rot(w70, 61) ^ (w70 >> 06);
          let w73 = w57 +% rot(w58, 01) ^ rot(w58, 08) ^ (w58 >> 07) +% w66 +% rot(w71, 19) ^ rot(w71, 61) ^ (w71 >> 06);
          let w74 = w58 +% rot(w59, 01) ^ rot(w59, 08) ^ (w59 >> 07) +% w67 +% rot(w72, 19) ^ rot(w72, 61) ^ (w72 >> 06);
          let w75 = w59 +% rot(w60, 01) ^ rot(w60, 08) ^ (w60 >> 07) +% w68 +% rot(w73, 19) ^ rot(w73, 61) ^ (w73 >> 06);
          let w76 = w60 +% rot(w61, 01) ^ rot(w61, 08) ^ (w61 >> 07) +% w69 +% rot(w74, 19) ^ rot(w74, 61) ^ (w74 >> 06);
          let w77 = w61 +% rot(w62, 01) ^ rot(w62, 08) ^ (w62 >> 07) +% w70 +% rot(w75, 19) ^ rot(w75, 61) ^ (w75 >> 06);
          let w78 = w62 +% rot(w63, 01) ^ rot(w63, 08) ^ (w63 >> 07) +% w71 +% rot(w76, 19) ^ rot(w76, 61) ^ (w76 >> 06);
          let w79 = w63 +% rot(w64, 01) ^ rot(w64, 08) ^ (w64 >> 07) +% w72 +% rot(w77, 19) ^ rot(w77, 61) ^ (w77 >> 06);

          t := h +% K00 +% w00 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K01 +% w01 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K02 +% w02 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K03 +% w03 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K04 +% w04 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K05 +% w05 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K06 +% w06 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K07 +% w07 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K08 +% w08 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K09 +% w09 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K10 +% w10 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K11 +% w11 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K12 +% w12 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K13 +% w13 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K14 +% w14 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K15 +% w15 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K16 +% w16 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K17 +% w17 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K18 +% w18 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K19 +% w19 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K20 +% w20 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K21 +% w21 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K22 +% w22 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K23 +% w23 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K24 +% w24 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K25 +% w25 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K26 +% w26 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K27 +% w27 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K28 +% w28 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K29 +% w29 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K30 +% w30 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K31 +% w31 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K32 +% w32 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K33 +% w33 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K34 +% w34 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K35 +% w35 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K36 +% w36 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K37 +% w37 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K38 +% w38 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K39 +% w39 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K40 +% w40 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K41 +% w41 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K42 +% w42 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K43 +% w43 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K44 +% w44 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K45 +% w45 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K46 +% w46 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K47 +% w47 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K48 +% w48 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K49 +% w49 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K50 +% w50 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K51 +% w51 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K52 +% w52 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K53 +% w53 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K54 +% w54 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K55 +% w55 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K56 +% w56 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K57 +% w57 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K58 +% w58 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K59 +% w59 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K60 +% w60 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K61 +% w61 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K62 +% w62 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K63 +% w63 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K64 +% w64 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K65 +% w65 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K66 +% w66 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K67 +% w67 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K68 +% w68 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K69 +% w69 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K70 +% w70 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K71 +% w71 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K72 +% w72 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K73 +% w73 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K74 +% w74 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K75 +% w75 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K76 +% w76 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K77 +% w77 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K78 +% w78 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t := h +% K79 +% w79 +% (e & f) ^ (^ e & g) +% rot(e, 14) ^ rot(e, 18) ^ rot(e, 41); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);

          // final addition
          a +%= a_0;
          b +%= b_0;
          c +%= c_0;
          d +%= d_0;
          e +%= e_0;
          f +%= f_0;
          g +%= g_0;
          h +%= h_0;

          // counters
          i_block +%= 1;
        };
      };
      // write state back to registers
      s0 := a;
      s1 := b;
      s2 := c;
      s3 := d;
      s4 := e;
      s5 := f;
      s6 := g;
      s7 := h;

      // write remaining bytes from backup to buffer
      var i = 0;
      while (i < pos) {
        writeByte(backup[i]);
        i += 1;
      };
    };

    public func write_iter_to_buffer(next : () -> ?Nat8) {
      loop {
        switch (next()) {
          case (?val) {
            // The following is an inlined version of writeByte(val)
            word := (word << 8) ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(val)));
            i_byte -%= 1;
            if (i_byte == 0) {
              msg[Nat8.toNat(i_msg)] := word;
              word := 0;
              i_byte := 8;
              i_msg +%= 1;
              if (i_msg == 16) return;
            };
          };
          case (null) return;
        };
      };
    };

    public func writeIter(iter : { next() : ?Nat8 }) : () {
      let next = iter.next;
      
      if (i_msg != 0 or i_byte != 8) {
        write_iter_to_buffer(next);
        if (i_msg == 16) {
          process_block_from_buffer();
          i_msg := 0;
          i_block +%= 1;
        };
      };

      if (i_msg != 0 or i_byte != 8) return;

      // must have buf.i_msg == 0 and buf.high == true here 
      // continue to try to read entire blocks at once from the iterator

      process_blocks_from_iter(next);
    };

    public func writeArray(arr : [Nat8]) : () {
      let s = arr.size();
      if (s == 0) return;
      var i = 0;
      if (i_msg > 0 or i_byte < 8) { 
        i := write_arr_to_buffer(arr,i);
      };
      i := process_blocks_from_arr(arr, i);
      ignore write_arr_to_buffer(arr, i);
    };

    public func writeBlob(blob : Blob) : () {
      let s = blob.size();
      if (s == 0) return;
      var i = 0;
      if (i_msg > 0 or i_byte < 8) { 
        i := write_blob_to_buffer(blob,i);
      };
      i := process_blocks_from_blob(blob, i);
      ignore write_blob_to_buffer(blob, i);
    };

    // Write blob to buffer until either the block is full or the end of the blob is reached
    // The return value refers to the interval that was written in the form [start,end)
    func write_blob_to_buffer(blob : Blob, start : Nat) : (end : Nat) {
      let s = blob.size();
      if (start >= s) return start;
      var i = start;
      while (i_byte < 8) {
        if (i == s) return s;
        writeByte(blob[i]);
        i += 1;
      };
      // round the remaining length of s - i down to a multiple of 8
      let i_max : Nat = i + ((s - i) / 8) * 8;
      while (i < i_max) {
        msg[Nat8.toNat(i_msg)] :=
        Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(blob[i]))) << 56
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(blob[i+1]))) << 48
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(blob[i+2]))) << 40
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(blob[i+3]))) << 32
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(blob[i+4]))) << 24
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(blob[i+5]))) << 16
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(blob[i+6]))) << 8
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(blob[i+7])));
        i += 8;
        i_msg +%= 1;
        if (i_msg == 16) {
          process_block_from_buffer();
          i_msg := 0;
          i_block +%= 1;
          return i;
        };
      };
      while (i < s) {
        writeByte(blob[i]);
        i += 1;
      };
      return i;
    };

    // Write blob to buffer until either the block is full or the end of the blob is reached
    // The return value refers to the interval that was written in the form [start,end)
    func write_arr_to_buffer(arr : [Nat8], start : Nat) : (end : Nat) {
      let s = arr.size();
      if (start >= s) return start;
      var i = start;
      while (i_byte < 8) {
        if (i == s) return s;
        writeByte(arr[i]);
        i += 1;
      };
      // round the remaining length of s - i down to a multiple of 8
      let i_max : Nat = i + ((s - i) / 8) * 8;
      while (i < i_max) {
        msg[Nat8.toNat(i_msg)] :=
        Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(arr[i]))) << 56
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(arr[i+1]))) << 48
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(arr[i+2]))) << 40
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(arr[i+3]))) << 32
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(arr[i+4]))) << 24
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(arr[i+5]))) << 16
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(arr[i+6]))) << 8
        ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(arr[i+7])));
        i += 8;
        i_msg +%= 1;
        if (i_msg == 16) {
          process_block_from_buffer();
          i_msg := 0;
          i_block +%= 1;
          return i;
        };
      };
      while (i < s) {
        writeByte(arr[i]);
        i += 1;
      };
      return i;
    };

    public func sum() : Blob {
      // calculate padding
      // t = bytes in the last incomplete block (0-127)
      let t : Nat8 = (i_msg << 3) +% 8 -% i_byte;
      // p = length of padding (1-128)
      var p : Nat8 = if (t < 112) (112 -% t) else (240 -% t);
      // n_bits = length of message in bits
      // Note: This implementation only handles messages < 2^64 bits
      let n_bits : Nat64 = ((i_block << 7) +% Nat64.fromIntWrap(Nat8.toNat(t))) << 3;

      // write 1-7 padding bytes 
      writeByte(0x80);
      p -%= 1;
      while (p & 0x7 != 0) {
        writeByte(0);
        p -%= 1;
      };
      // write padding words
      p >>= 3;
      while (p != 0) {
        writeWord(0);
        p -%= 1;
      };

      // write length (16 bytes)
      // Note: this exactly fills the block buffer, hence process_block will get
      // triggered by the last writeByte
      writeWord(0);
      writeWord(n_bits);

      // retrieve sum
      let (d0, d1, d2, d3, d4, d5, d6, d7) = Prim.explodeNat64(s0);
      let (d8, d9, d10, d11, d12, d13, d14, d15) = Prim.explodeNat64(s1);
      let (d16, d17, d18, d19, d20, d21, d22, d23) = Prim.explodeNat64(s2);
      let (d24, d25, d26, d27, d28, d29, d30, d31) = Prim.explodeNat64(s3);

      if (algo_ == #sha512_224) {
        return Prim.arrayToBlob([
          d0, d1, d2, d3, d4, d5, d6, d7,
          d8, d9, d10, d11, d12, d13, d14, d15,
          d16, d17, d18, d19, d20, d21, d22, d23,
          d24, d25, d26, d27
        ]);
      };

      if (algo_ == #sha512_256) {
        return Prim.arrayToBlob([
          d0, d1, d2, d3, d4, d5, d6, d7,
          d8, d9, d10, d11, d12, d13, d14, d15,
          d16, d17, d18, d19, d20, d21, d22, d23,
          d24, d25, d26, d27,
          d28, d29, d30, d31
        ]);
      };

      let (d32, d33, d34, d35, d36, d37, d38, d39) = Prim.explodeNat64(s4);
      let (d40, d41, d42, d43, d44, d45, d46, d47) = Prim.explodeNat64(s5);

      if (algo_ == #sha384) {
        return Prim.arrayToBlob([
          d0, d1, d2, d3, d4, d5, d6, d7,
          d8, d9, d10, d11, d12, d13, d14, d15,
          d16, d17, d18, d19, d20, d21, d22, d23,
          d24, d25, d26, d27, d28, d29, d30, d31,
          d32, d33, d34, d35, d36, d37, d38, d39,
          d40, d41, d42, d43, d44, d45, d46, d47
        ]);
      };

      let (d48, d49, d50, d51, d52, d53, d54, d55) = Prim.explodeNat64(s6);
      let (d56, d57, d58, d59, d60, d61, d62, d63) = Prim.explodeNat64(s7);

      return Prim.arrayToBlob([
        d0, d1, d2, d3, d4, d5, d6, d7,
        d8, d9, d10, d11, d12, d13, d14, d15,
        d16, d17, d18, d19, d20, d21, d22, d23,
        d24, d25, d26, d27, d28, d29, d30, d31,
        d32, d33, d34, d35, d36, d37, d38, d39,
        d40, d41, d42, d43, d44, d45, d46, d47,
        d48, d49, d50, d51, d52, d53, d54, d55,
        d56, d57, d58, d59, d60, d61, d62, d63
      ]);
    };
  }; // class Digest

  // Calculate SHA2 hash digest from Iter.
  public func fromIter(algo : Algorithm, iter : { next() : ?Nat8 }) : Blob {
    let digest = Digest(algo);
    digest.writeIter(iter);
    return digest.sum();
  };

  // Calculate SHA256 hash digest from [Nat8].
  public func fromArray(algo : Algorithm, arr : [Nat8]) : Blob {
    let digest = Digest(algo);
    digest.writeArray(arr);
    return digest.sum();
  };

  // Calculate SHA2 hash digest from Blob.
  public func fromBlob(algo : Algorithm, b : Blob) : Blob {
    let digest = Digest(algo);
    digest.writeBlob(b);
    return digest.sum();
  };
};
