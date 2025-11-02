import Nat "mo:core/Nat";
import VarArray "mo:core/VarArray";
import Prim "mo:prim";

import fromBlob "whole_blocks/blob";
import fromArray "whole_blocks/array";
import fromVarArray "whole_blocks/varArray";
import fromPositional "whole_blocks/positional";
import fromNext "whole_blocks/next";

import Block "block";

module {
  // indices 0,2,4,6,8,10,12,14 = high bytes, indices 1,3,5,7,9,11,13,15 = low bytes
  public type Self = [var Nat16];

  public func set(self : Self, vals : [Nat16]) {
    for (i in Nat.range(0, 16)) self[i] := vals[i];
  };
  public let clone = VarArray.clone;
  public let process_blocks_from_blob = fromBlob.process_blocks;
  public let process_blocks_from_array = fromArray.process_blocks;
  public let process_blocks_from_vararray = fromVarArray.process_blocks;
  public let process_blocks_from_func = fromPositional.process_blocks;
  public let process_blocks_from_stream = fromNext.process_blocks;
  public let process_block_from_msg = Block.process_block;

  public func toNat8Array(self : Self, len : Nat) : [Nat8] {
    let (d0, d1) = Prim.explodeNat16(self[0]);
    let (d2, d3) = Prim.explodeNat16(self[1]);
    let (d4, d5) = Prim.explodeNat16(self[2]);
    let (d6, d7) = Prim.explodeNat16(self[3]);
    let (d8, d9) = Prim.explodeNat16(self[4]);
    let (d10, d11) = Prim.explodeNat16(self[5]);
    let (d12, d13) = Prim.explodeNat16(self[6]);
    let (d14, d15) = Prim.explodeNat16(self[7]);
    let (d16, d17) = Prim.explodeNat16(self[8]);
    let (d18, d19) = Prim.explodeNat16(self[9]);
    let (d20, d21) = Prim.explodeNat16(self[10]);
    let (d22, d23) = Prim.explodeNat16(self[11]);
    let (d24, d25) = Prim.explodeNat16(self[12]);
    let (d26, d27) = Prim.explodeNat16(self[13]);

    if (len == 28) return [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15, d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27];

    let (d28, d29) = Prim.explodeNat16(self[14]);
    let (d30, d31) = Prim.explodeNat16(self[15]);

    return [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15, d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27, d28, d29, d30, d31];
  };

};
