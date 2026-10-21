import Prim "mo:prim";

module {
  let nat32To16 = Prim.nat32ToNat16;
  let nat16To32 = Prim.nat16ToNat32;

  func rot(x : Nat32, y : Nat32) : Nat32 = x <>> y;

  /// Run the SHA256 compression on the padding block of a 64-byte message
  /// (bit length 512): the second block of every `Hasher` combine. The 16
  /// message words of this block are fixed (`w00 = 0x80000000`, `w01..w14 = 0`,
  /// `w15 = 512`), so the whole message schedule `w16..w63` is fixed too, and
  /// each round's `K[i] +% w[i]` is one constant. These 64 constants are
  /// precomputed and inlined below, so only the 64 rounds remain, with no
  /// schedule computation and no dependence on compiler constant folding.
  /// `test/hasher.test.mo` checks every combine against the `Digest` path,
  /// which validates the constants. Updates the 16 half-word state `self` in
  /// place.
  public func process(self : [var Nat16]) : () {
    // load state registers
    var a = nat16To32(self[0]) << 16 | nat16To32(self[1]);
    var b = nat16To32(self[2]) << 16 | nat16To32(self[3]);
    var c = nat16To32(self[4]) << 16 | nat16To32(self[5]);
    var d = nat16To32(self[6]) << 16 | nat16To32(self[7]);
    var e = nat16To32(self[8]) << 16 | nat16To32(self[9]);
    var f = nat16To32(self[10]) << 16 | nat16To32(self[11]);
    var g = nat16To32(self[12]) << 16 | nat16To32(self[13]);
    var h = nat16To32(self[14]) << 16 | nat16To32(self[15]);
    var t = 0 : Nat32;

    let a_0 = a;
    let b_0 = b;
    let c_0 = c;
    let d_0 = d;
    let e_0 = e;
    let f_0 = f;
    let g_0 = g;
    let h_0 = h;

    // Each round adds the constant K[i] +% w[i] of the fixed padding block.
    // prettier-ignore
    do {
      t := h +% 0xc28a2f98 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x71374491 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xb5c0fbcf +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xe9b5dba5 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x3956c25b +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x59f111f1 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x923f82a4 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xab1c5ed5 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xd807aa98 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x12835b01 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x243185be +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x550c7dc3 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x72be5d74 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x80deb1fe +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x9bdc06a7 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xc19bf374 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x649b69c1 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xf0fe4786 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x0fe1edc6 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x240cf254 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x4fe9346f +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x6cc984be +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x61b9411e +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x16f988fa +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xf2c65152 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xa88e5a6d +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xb019fc65 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xb9d99ec7 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x9a1231c3 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xe70eeaa0 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xfdb1232b +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xc7353eb0 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x3069bad5 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xcb976d5f +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x5a0f118f +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xdc1eeefd +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x0a35b689 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xde0b7a04 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x58f4ca9d +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xe15d5b16 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x007f3e86 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x37088980 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xa507ea32 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x6fab9537 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x17406110 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x0d8cd6f1 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xcdaa3b6d +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xc0bbbe37 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x83613bda +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xdb48a363 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x0b02e931 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x6fd15ca7 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x521afaca +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x31338431 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x6ed41a95 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x6d437890 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xc39c91f2 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x9eccabbd +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xb5c9a0e6 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x532fb63c +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xd2c741c6 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x07237ea3 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0xa4954b68 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
      t := h +% 0x4c191d76 +% (e & f) ^ (^ e & g) +% rot(e, 06) ^ rot(e, 11) ^ rot(e, 25); h := g; g := f; f := e; e := d +% t; d := c; c := b; b := a; a := t +% (b & c) ^ (b & d) ^ (c & d) +% rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
    };

    a +%= a_0;
    b +%= b_0;
    c +%= c_0;
    d +%= d_0;
    e +%= e_0;
    f +%= f_0;
    g +%= g_0;
    h +%= h_0;

    self[0] := nat32To16(a >> 16);
    self[1] := nat32To16(a & 0xffff);
    self[2] := nat32To16(b >> 16);
    self[3] := nat32To16(b & 0xffff);
    self[4] := nat32To16(c >> 16);
    self[5] := nat32To16(c & 0xffff);
    self[6] := nat32To16(d >> 16);
    self[7] := nat32To16(d & 0xffff);
    self[8] := nat32To16(e >> 16);
    self[9] := nat32To16(e & 0xffff);
    self[10] := nat32To16(f >> 16);
    self[11] := nat32To16(f & 0xffff);
    self[12] := nat32To16(g >> 16);
    self[13] := nat32To16(g & 0xffff);
    self[14] := nat32To16(h >> 16);
    self[15] := nat32To16(h & 0xffff);
  };
};
