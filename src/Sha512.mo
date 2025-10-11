/// Cycle-optimized Sha512 variants.
///
/// Features:
///
/// * Algorithms: `sha512_224`, `sha512_256`, `sha384`, `sha512`
/// * Input types: `Blob`, `[Nat8]`, `Iter<Nat8>`
/// * Output types: `Blob`

import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Types "mo:core/Types";
import VarArray "mo:core/VarArray";
import Prim "mo:prim";
import K "sha512/constants";
import ProcessBlock "sha512/process_block";
import Byte "sha512/write/byte";
import Write "sha512/write";

module {
  public type Self = Digest;

  public type Algorithm = {
    #sha384;
    #sha512;
    #sha512_224;
    #sha512_256;
  };

  public type Digest = {
    algo : Algorithm;
    // msg buffer
    msg : [var Nat64];
    var word : Nat64;
    var i_msg : Nat8;
    var i_byte : Nat8;
    var i_block : Nat64;
    // state variables
    s : [var Nat64];
    var closed : Bool;
  };

  public func new(algo_ : Algorithm) : Digest {
    {
      algo = algo_;
      msg : [var Nat64] = [var 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      var i_msg : Nat8 = 0;
      var i_byte : Nat8 = 8;
      var i_block : Nat64 = 0;
      var word : Nat64 = 0;
      s : [var Nat64] = switch (algo_) {
        case (#sha512_224) [ var 0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf, 0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1, ];
        case (#sha512_256) [ var 0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2, ];
        case (#sha384) [ var 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4, ];
        case (#sha512) [ var 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179, ];
      };
      var closed = false;
    }
  };

  public func reset(x : Digest) {
    assert not x.closed;
    x.i_msg := 0;
    x.i_byte := 8;
    x.i_block := 0;
    let i = switch (x.algo) {
      case (#sha512_224) 0;
      case (#sha512_256) 1;
      case (#sha384) 2;
      case (#sha512) 3;
    };
    for (j in Nat.range(0, 8)) {
      x.s[j] := K.ivs[i][j];
    };
  };
  
  public func clone(x : Digest) : Digest {
    assert not x.closed;
    {
      algo = x.algo;
      msg = VarArray.clone(x.msg);
      var word = x.word;
      var i_msg = x.i_msg;
      var i_byte = x.i_byte;
      var i_block = x.i_block;
      s = VarArray.clone(x.s);
      var closed = false;
    };
  };

  // We must be at a word boundary, i.e. i_byte must be equal to 8
  private func writeWord(x : Digest, val : Nat64) : () {
    assert (x.i_byte == 8);
    x.msg[Nat8.toNat(x.i_msg)] := val;
    x.i_msg +%= 1;
    if (x.i_msg == 16) {
      ProcessBlock.process_block_from_buffer(x.s, x.msg);
      x.i_msg := 0;
      x.i_block +%= 1;
    };
  };

  /*
  public func writeIter2(x : Digest, iter : { next() : ?Nat8 }) : () {
    assert not x.closed;
    var word = x.word;
    var i_byte = x.i_byte;
    var i_msg = x.i_msg;
    var i_block = x.i_block;
    let next = iter.next;
    label reading loop {
      switch (next()) {
        case (?val) {
          // The following is an inlined version of writeByte(val)
          word := (word << 8) ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(val)));
          i_byte -%= 1;
          if (i_byte == 0) {
            x.msg[Nat8.toNat(i_msg)] := word;
            word := 0;
            i_byte := 8;
            i_msg +%= 1;
            if (i_msg == 16) {
              ProcessBlock.process_block_from_buffer(x.s, x.msg);
              i_msg := 0;
              i_block +%= 1;
            };
          };
          continue reading;
        };
        case (null) {
          break reading;
        };
      };
    };
    x.word := word;
    x.i_byte := i_byte;
    x.i_msg := i_msg;
    x.i_block := i_block;
  };
  */

  public func writeBlob(x : Digest, data : Blob) : () = Write.blob(x, data);
  public func writeArray(x : Digest, data : [Nat8]) : () = Write.array(x, data);
  public func writeVarArray(x : Digest, data : [var Nat8]) : () = Write.varArray(x, data);
  public func writeList(x : Digest, data : Types.List<Nat8>) : () = Write.list(x, data);
  public func writeIter(x : Digest, data : Types.Iter<Nat8>) : () = Write.iter(x, data.next);

  public func sum(x : Digest) : Blob {
    assert not x.closed;
    x.closed := true;
    // calculate padding
    // t = bytes in the last incomplete block (0-127)
    let t : Nat8 = (x.i_msg << 3) +% 8 -% x.i_byte;
    // p = length of padding (1-128)
    var p : Nat8 = if (t < 112) (112 -% t) else (240 -% t);
    // n_bits = length of message in bits
    // Note: This implementation only handles messages < 2^64 bits
    let n_bits : Nat64 = ((x.i_block << 7) +% Nat64.fromIntWrap(Nat8.toNat(t))) << 3;

    // write 1-7 padding bytes 
    Byte.writeByte(x, 0x80);
    p -%= 1;
    while (p & 0x7 != 0) {
      Byte.writeByte(x, 0);
      p -%= 1;
    };
    // write padding words
    p >>= 3;
    while (p != 0) {
      writeWord(x, 0);
      p -%= 1;
    };

    // write length (16 bytes)
    // Note: this exactly fills the block buffer, hence process_block will get
    // triggered by the last writeByte
    writeWord(x, 0);
    writeWord(x, n_bits);

    // retrieve sum
    stateToBlob(x);
  };

  func stateToBlob(x : Digest) : Blob {
    let (d0, d1, d2, d3, d4, d5, d6, d7) = Prim.explodeNat64(x.s[0]);
    let (d8, d9, d10, d11, d12, d13, d14, d15) = Prim.explodeNat64(x.s[1]);
    let (d16, d17, d18, d19, d20, d21, d22, d23) = Prim.explodeNat64(x.s[2]);
    let (d24, d25, d26, d27, d28, d29, d30, d31) = Prim.explodeNat64(x.s[3]);

    if (x.algo == #sha512_224) {
      return Prim.arrayToBlob([
        d0, d1, d2, d3, d4, d5, d6, d7,
        d8, d9, d10, d11, d12, d13, d14, d15,
        d16, d17, d18, d19, d20, d21, d22, d23,
        d24, d25, d26, d27
      ]);
    };

    if (x.algo == #sha512_256) {
      return Prim.arrayToBlob([
        d0, d1, d2, d3, d4, d5, d6, d7,
        d8, d9, d10, d11, d12, d13, d14, d15,
        d16, d17, d18, d19, d20, d21, d22, d23,
        d24, d25, d26, d27,
        d28, d29, d30, d31
      ]);
    };

    let (d32, d33, d34, d35, d36, d37, d38, d39) = Prim.explodeNat64(x.s[4]);
    let (d40, d41, d42, d43, d44, d45, d46, d47) = Prim.explodeNat64(x.s[5]);

    if (x.algo == #sha384) {
      return Prim.arrayToBlob([
        d0, d1, d2, d3, d4, d5, d6, d7,
        d8, d9, d10, d11, d12, d13, d14, d15,
        d16, d17, d18, d19, d20, d21, d22, d23,
        d24, d25, d26, d27, d28, d29, d30, d31,
        d32, d33, d34, d35, d36, d37, d38, d39,
        d40, d41, d42, d43, d44, d45, d46, d47
      ]);
    };

    let (d48, d49, d50, d51, d52, d53, d54, d55) = Prim.explodeNat64(x.s[6]);
    let (d56, d57, d58, d59, d60, d61, d62, d63) = Prim.explodeNat64(x.s[7]);

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

  public func peekSum(x : Digest) : Blob {
    if (x.closed) stateToBlob(x) else sum(clone(x));
  };

  // Calculate SHA2 hash digest from Iter, Array, Blob, VarArray, List.
  public func fromIter(algo : Algorithm, iter : { next() : ?Nat8 }) : Blob {
    let d = new(algo);
    writeIter(d, iter);
    return sum(d);
  };
  public func fromArray(algo : Algorithm, arr : [Nat8]) : Blob {
    let d = new(algo);
    writeArray(d, arr);
    return sum(d);
  };
  public func fromBlob(algo : Algorithm, b : Blob) : Blob {
    let d = new(algo);
    writeBlob(d, b);
    return sum(d);
  };
  public func fromVarArray(algo : Algorithm, arr : [var Nat8]) : Blob {
    let d = new(algo);
    writeVarArray(d, arr);
    return sum(d);
  };
  public func fromList(algo : Algorithm, l : Types.List<Nat8>) : Blob {
    let d = new(algo);
    writeList(d, l);
    return sum(d);
  };

};
