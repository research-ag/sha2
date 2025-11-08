import Array "./write/array";
import Blob "./write/blob";
import VarArray "./write/varArray";
import Accessor "./write/accessor";
import Reader "./write/reader";
import Iter "./write/iter";
import Buffer "../buffer";
import State "../state";
import { type Digest } "../types";

module {
  public func writeBlob(self : Digest, data : Blob) {
    assert not self.closed;
    Blob.write(self, data);
  };
  public func writeArray(self : Digest, data : [Nat8]) {
    assert not self.closed;
    Array.write(self, data);
  };
  public func writeVarArray(self : Digest, data : [var Nat8]) {
    assert not self.closed;
    VarArray.write(self, data);
  };
  public func writeAccessor(self : Digest, data : Nat -> Nat8, start : Nat, len : Nat) {
    assert not self.closed;
    Accessor.write(self, data, start, len);
  };
  public func writeReader(self : Digest, data : () -> Nat8, len : Nat) {
    assert not self.closed;
    Reader.write(self, data, len);
  };
  public func writeIter(self : Digest, data : () -> ?Nat8) {
    assert not self.closed;
    Iter.write(self, data);
  };
};