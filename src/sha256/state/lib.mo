import Nat "mo:core/Nat";
import Types "mo:core/Types";
import VarArray "mo:core/VarArray";
import Prim "mo:prim";

import ProcessBlob "blocks/Blob";
import ProcessArray "blocks/Array";
import ProcessList "blocks/List";
import ProcessVarArray "blocks/VarArray";

import Block "block";

module {
  // Self.0 = high bytes, Self.1 = low bytes
  public type Self = ([var Nat16], [var Nat16]);

  public func set(s : Self, high : [Nat16], low : [Nat16]) {
    for (i in Nat.range(0, 8)) {
      s.0 [i] := high[i];
      s.1 [i] := low[i];
    };
  };
  public func clone(s : Self) : Self = (VarArray.clone(s.0), VarArray.clone(s.1));
  public func process_blocks_from_blob(s : Self, data : Blob, start : Nat) : Nat {
    ProcessBlob.process_blocks(s.0, s.1, data, start);
  };
  public func process_blocks_from_array(s : Self, data : [Nat8], start : Nat) : Nat {
    ProcessArray.process_blocks(s.0, s.1, data, start);
  };
  public func process_blocks_from_vararray(s : Self, data : [var Nat8], start : Nat) : Nat {
    ProcessVarArray.process_blocks(s.0, s.1, data, start);
  };
  public func process_blocks_from_list(s : Self, data : Types.List<Nat8>, start : Nat) : Nat {
    ProcessList.process_blocks(s.0, s.1, data, start);
  };
  public func process_block_from_msg(s : Self, msg : [var Nat16]) {
    Block.process_block(s.0, s.1, msg);
  };
  public func toArray28(s : Self) : [Nat8] {
    let (d0, d1) = Prim.explodeNat16(s.0 [0]);
    let (d2, d3) = Prim.explodeNat16(s.1 [0]);
    let (d4, d5) = Prim.explodeNat16(s.0 [1]);
    let (d6, d7) = Prim.explodeNat16(s.1 [1]);
    let (d8, d9) = Prim.explodeNat16(s.0 [2]);
    let (d10, d11) = Prim.explodeNat16(s.1 [2]);
    let (d12, d13) = Prim.explodeNat16(s.0 [3]);
    let (d14, d15) = Prim.explodeNat16(s.1 [3]);
    let (d16, d17) = Prim.explodeNat16(s.0 [4]);
    let (d18, d19) = Prim.explodeNat16(s.1 [4]);
    let (d20, d21) = Prim.explodeNat16(s.0 [5]);
    let (d22, d23) = Prim.explodeNat16(s.1 [5]);
    let (d24, d25) = Prim.explodeNat16(s.0 [6]);
    let (d26, d27) = Prim.explodeNat16(s.1 [6]);

    [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15, d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27];
  };

  public func toArray32(s : Self) : [Nat8] {
    let (d0, d1) = Prim.explodeNat16(s.0 [0]);
    let (d2, d3) = Prim.explodeNat16(s.1 [0]);
    let (d4, d5) = Prim.explodeNat16(s.0 [1]);
    let (d6, d7) = Prim.explodeNat16(s.1 [1]);
    let (d8, d9) = Prim.explodeNat16(s.0 [2]);
    let (d10, d11) = Prim.explodeNat16(s.1 [2]);
    let (d12, d13) = Prim.explodeNat16(s.0 [3]);
    let (d14, d15) = Prim.explodeNat16(s.1 [3]);
    let (d16, d17) = Prim.explodeNat16(s.0 [4]);
    let (d18, d19) = Prim.explodeNat16(s.1 [4]);
    let (d20, d21) = Prim.explodeNat16(s.0 [5]);
    let (d22, d23) = Prim.explodeNat16(s.1 [5]);
    let (d24, d25) = Prim.explodeNat16(s.0 [6]);
    let (d26, d27) = Prim.explodeNat16(s.1 [6]);
    let (d28, d29) = Prim.explodeNat16(s.0 [7]);
    let (d30, d31) = Prim.explodeNat16(s.1 [7]);

    [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15, d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27, d28, d29, d30, d31];
  };
};
