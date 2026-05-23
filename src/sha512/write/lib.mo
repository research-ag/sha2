import Array "./array";
import Blob "./blob";
import VarArray "./varArray";
import Accessor "./accessor";
import Reader "./reader";
import Iter "./iter";

module {
  /// Internal SHA512 digest state shared by all writer dispatch functions.
  public type Digest = {
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

  /// Dispatch a `Blob` write to the SHA512 block processor. Traps if `x` is closed.
  public func blob(x : Digest, data : Blob) {
    assert not x.closed;
    Blob.write(x, data);
  };
  /// Dispatch a `[Nat8]` write to the SHA512 block processor. Traps if `x` is closed.
  public func array(x : Digest, data : [Nat8]) {
    assert not x.closed;
    Array.write(x, data);
  };
  /// Dispatch a `[var Nat8]` write to the SHA512 block processor. Traps if `x` is closed.
  public func varArray(x : Digest, data : [var Nat8]) {
    assert not x.closed;
    VarArray.write(x, data);
  };
  /// Dispatch a positional-accessor write (`len` bytes starting at `start`) to the SHA512 block processor. Traps if `x` is closed.
  public func accessor(x : Digest, data : Nat -> Nat8, start : Nat, len : Nat) : () {
    assert not x.closed;
    Accessor.write(x, data, start, len);
  };
  /// Dispatch a reader-function write (`len` calls to `data`) to the SHA512 block processor. Traps if `x` is closed.
  public func reader(x : Digest, data : () -> Nat8, len : Nat) : () {
    assert not x.closed;
    Reader.write(x, data, len);
  };
  /// Dispatch an iterator write (consumes until the iterator returns `null`) to the SHA512 block processor. Traps if `x` is closed.
  public func iter(x : Digest, data : () -> ?Nat8) {
    assert not x.closed;
    Iter.write(x, data);
  };
};
