import List "mo:core/List";
import Nat32 "mo:base/Nat32";
import Prim "mo:prim";

module {
  func locate(index : Nat) : (Nat, Nat) {
    // see comments in tests
    let i = Nat32.fromNat(index);
    let lz = Nat32.bitcountLeadingZero(i);
    let lz2 = lz >> 1;
    if (lz & 1 == 0) {
      (Nat32.toNat(((i << lz2) >> 16) ^ (0x10000 >> lz2)), Nat32.toNat(i & (0xFFFF >> lz2)))
    } else {
      (Nat32.toNat(((i << lz2) >> 15) ^ (0x18000 >> lz2)), Nat32.toNat(i & (0x7FFF >> lz2)))
    }
  };

  public func listRange<T>(list : List.List<T>, start : Nat) : () -> T {
    var blockIndex = 0;
    var elementIndex = 0;
    if (start != 0) {
      let (block, element) = locate(start - 1);
      blockIndex := block;
      elementIndex := element + 1
    };
    var db : [var ?T] = list.blocks[blockIndex];
    var dbSize = db.size();
    func next() : T {
      // Note: next() traps when reading beyond end of list
      if (elementIndex == dbSize) {
        blockIndex += 1;
        db := list.blocks[blockIndex];
        dbSize := db.size();
        elementIndex := 0
      };
      switch (db[elementIndex]) {
        case (?ret) {
          elementIndex += 1;
          return ret
        };
        case (_) Prim.trap("");
      };
    };
    next
  };
}