/// SHA256 internal types.

module {
  /// Message buffer.
  /// `msg`: block buffer, one 64-byte block as 32 half-words of 16 bits.
  /// `i_msg`: number of complete half-words in `msg`.
  /// `i_block`: number of 64-byte blocks processed so far.
  /// `high`: whether the next byte goes into the high byte of a new half-word
  /// (true) or completes the half-word started in `word` (false).
  /// `word`: the half-word being built while `high` is false (its high byte).
  public type Buffer = {
    msg : [var Nat16];
    var i_msg : Nat8;
    var i_block : Nat64;
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
