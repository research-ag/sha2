module {
  public type Buffer = {
    msg : [var Nat16];
    var i_msg : Nat8;
    var i_block : Nat32;
    var high : Bool;
    var word : Nat16;
  };

  public type State = [var Nat16];

  // Digest type without the algorithm field
  public type Digest = {
    buffer : Buffer;
    state : State;
    var closed : Bool;
  };
}
