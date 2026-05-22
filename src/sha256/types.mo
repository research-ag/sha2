/// SHA256 internal types.

module {
  /// Message buffer.
  /// `msg`: block buffer (16 words of 16 bits).
  /// `i_msg`: current word index in `msg`.
  /// `i_block`: total number of bits hashed so far.
  /// `high`: whether we are in the high byte of the current word.
  /// `word`: current word being built.
  public type Buffer = {
    msg : [var Nat16];
    var i_msg : Nat8;
    var i_block : Nat32;
    var high : Bool;
    var word : Nat16;
  };

  /// SHA256 state (8 words of 32 bits, represented as 16 words of 16 bits).
  public type State = [var Nat16];

  /// Digest type without the algorithm field.
  /// `buffer`: message buffer.
  /// `state`: current hash state.
  /// `closed`: whether the digest has been finalized.
  public type Digest = {
    buffer : Buffer;
    state : State;
    var closed : Bool;
  };
};
