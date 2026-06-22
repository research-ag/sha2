import Nat "mo:core/Nat";
import VarArray "mo:core/VarArray";
import Prim "mo:prim";

import fromBlob "process/blocks/blob";
import fromMerge "process/blocks/merge";
import fromLeaf "process/blocks/leaf";
import fromArray "process/blocks/array";
import fromVarArray "process/blocks/varArray";
import fromAccessor "process/blocks/accessor";
import fromReader "process/blocks/reader";
import fromMsg "process/msg_buffer";
import fromPadding "process/padding";
import fromFold "process/fold";

module {
  /// SHA256 internal state — 8 state words split into 16 `Nat16` half-words (even indices hold the high byte, odd indices the low byte).
  // indices 0,2,4,6,8,10,12,14 = high bytes, indices 1,3,5,7,9,11,13,15 = low bytes
  public type State = [var Nat16];

  /// Overwrite the 16 half-words of `self` with the first 16 entries of `vals`.
  public func set(self : State, vals : [Nat16]) {
    for (i in Nat.range(0, 16)) self[i] := vals[i];
  };
  /// Return an independent copy of the state array.
  public let clone = VarArray.clone;
  /// Run the SHA256 compression on every full 64-byte block in the input `Blob` (see `process/blocks/blob`).
  public let process_blocks_from_blob = fromBlob.process;
  /// Inner block of a merge: hash one block of `self`'s digest ++ `sb` from the IV, overwriting `self` (see `process/blocks/merge`).
  public let process_merge_block = fromMerge.process;
  /// Inner block of a leaf combine: hash one block of `b1 ++ b2` (two 32-byte blobs) from the IV, overwriting `self` (see `process/blocks/leaf`).
  public let process_leaf_block = fromLeaf.process;
  /// Run the SHA256 compression on every full 64-byte block in the input `[Nat8]` (see `process/blocks/array`).
  public let process_blocks_from_array = fromArray.process;
  /// Run the SHA256 compression on every full 64-byte block in the input `[var Nat8]` (see `process/blocks/varArray`).
  public let process_blocks_from_vararray = fromVarArray.process;
  /// Run the SHA256 compression on every full 64-byte block read via a positional accessor (see `process/blocks/accessor`).
  public let process_blocks_from_accessor = fromAccessor.process;
  /// Run the SHA256 compression on every full 64-byte block read via a reader function (see `process/blocks/reader`).
  public let process_blocks_from_reader = fromReader.process;
  /// Run the SHA256 compression on a single block already loaded into the message buffer (see `process/msg_buffer`).
  public let process_block_from_msg = fromMsg.process;
  /// Run the SHA256 compression on the all-constant final padding block for a block-aligned message, encoding only the bit length (see `process/padding`).
  public let process_padding_block = fromPadding.process;
  /// Hash the 32-byte digest held in the state as a fresh message in one specialized block, overwriting the state with `SHA256(state)` (see `process/fold`).
  public let process_fold_block = fromFold.process;

  /// Serialize `self` as a `[Nat8]` of the requested truncation length: `28` for SHA-224 or `32` for SHA-256.
  public func toNat8Array(self : State, len : Nat) : [Nat8] {
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
