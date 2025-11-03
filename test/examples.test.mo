import Sha256 "../src/Sha256";
import Sha512 "../src/Sha512";
import Blob "mo:core/Blob";
import List "mo:core/List";
import _ListTools "../src/util/List";
import { print } "mo:core/Debug";

func prt(b : Blob) = print(debug_show b);

prt (Sha256.fromBlob("")); // default algo #sha256
prt (Sha256.fromBlob(#sha224, ""));

prt (Sha512.fromBlob("")); // default algo #sha512
prt (Sha512.fromBlob(#sha512_224, ""));
prt (Sha512.fromBlob(#sha512_256, ""));
prt (Sha512.fromBlob(#sha384, ""));

prt (Sha256.fromArray([]));
prt (Sha256.fromVarArray([var]));
prt (Sha256.fromIter({ next = func () : ?Nat8 = null }));
prt (Sha256.fromUncheckedReader(func () : Nat8 = 0, 0));
prt (Sha256.fromUncheckedAccessor(func (i : Nat) : Nat8 = 0, 0, 0));

do {
  let l = List.empty<Nat8>();
  prt (Sha256.fromIter(List.values(l)));
  prt (Sha256.fromUncheckedReader(l.stream(), l.size()));
};

do {
  let l = List.fromArray(Blob.toArray("hello world!"));
  prt (Sha256.fromUncheckedReader(l.stream(), 5));
  prt (Sha256.fromUncheckedReader(l.stream(), l.size()));
  prt (Sha256.fromUncheckedReader(l.stream(6), 5));
  prt (Sha256.fromBlob("world"));
  func at(i : Nat) : Nat8 = List.at(l, i);
  prt (Sha256.fromUncheckedAccessor(at, 6, 5));
};
/*
do {
  let digest = Sha256.new(); // default algo #sha256 
  digest.writeBlob("hello");
  prt (digest.peekSum());
  digest.writeBlob(" world!");
  prt (digest.sum());
}
*/