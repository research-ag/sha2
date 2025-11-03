import Array "./array";
import Blob "./blob";
import VarArray "./varArray";
import Accessor "./accessor";
import Reader "./reader";
import Iter "./iter";
import Buffer "../buffer";
import State "../state";

module {
  type Digest = {
    buffer : Buffer.Buffer;
    state : State.State;
    var closed : Bool;
  };
  public func blob(x : Digest, data : Blob) {
    assert not x.closed;
    Blob.write(x, data);
  };
  public func array(x : Digest, data : [Nat8]) {
    assert not x.closed;
    Array.write(x, data);
  };
  public func varArray(x : Digest, data : [var Nat8]) {
    assert not x.closed;
    VarArray.write(x, data);
  };
  public func accessor(x : Digest, data : Nat -> Nat8, start : Nat, len : Nat) {
    assert not x.closed;
    Accessor.write(x, data, start, len);
  };
  public func reader(x : Digest, data : () -> Nat8, len : Nat) {
    assert not x.closed;
    Reader.write(x, data, len);
  };
  public func iter(x : Digest, data : () -> ?Nat8) {
    assert not x.closed;
    Iter.write(x, data);
  };
};