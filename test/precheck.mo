import Debug "mo:base/Debug";

let x = 1;
let y = 2;

func add(x : (implicit : Nat), y : (implicit : Nat)) : Nat {
  return x + y;
};

module M {
  public let step = 1;
  public func next(x : Nat, step : (implicit : Nat)) : Nat { x + step };
};

let step = 2;
let r = M.next(0);

Debug.print(debug_show r);

module N {
  public func f(self : Nat) {};
};
(0).f();

/*
module {
  public func g(self : Nat) {};
  func h() {
    (0).g();
  };
};
*/

type X = {
  a : Nat;
};

type Y = {
  b : Nat;
};

type Z = X and Y;
