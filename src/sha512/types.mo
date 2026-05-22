/// SHA512 internal types.

module {
  /// Digest type.
  /// `msg`: message block buffer (16 words of 64 bits).
  /// `word`: current word being built.
  /// `i_msg`: current word index in `msg`.
  /// `i_byte`: current byte index in `word`.
  /// `i_block`: total number of bits hashed so far.
  /// `s`: current hash state (8 words of 64 bits).
  /// `closed`: whether the digest has been finalized.
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
};
