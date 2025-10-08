import Array "./array";
import Blob "./blob";
import VarArray "./varArray";
import Pos "./positional";
import Next "./next";
import Buffer "../buffer";
import State "../state";

module {
  type Digest = {
    buffer : Buffer.Self;
    state : State.Self;
    var closed : Bool;
  };
  public func blob(x : Digest, data : Blob) : () {
    assert not x.closed;
    Blob.write(x, data);
  };
  public func array(x : Digest, data : [Nat8]) : () {
    assert not x.closed;
    Array.write(x, data);
  };
  public func varArray(x : Digest, data : [var Nat8]) : () {
    assert not x.closed;
    VarArray.write(x, data);
  };
  public func positional(x : Digest, data : Nat -> Nat8, sz : Nat) : () {
    assert not x.closed;
    Pos.write(x, data, sz);
  };
  public func next(x : Digest, data : () -> Nat8, sz : Nat) : () {
    assert not x.closed;
    Next.write(x, data, sz);
  };
};