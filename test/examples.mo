import Sha256 "../src/Sha256";
import Sha512 "../src/Sha512";
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
prt (Sha256.fromNext(func () : Nat8 = 0, 0));
prt (Sha256.fromPositional(func (i : Nat) : Nat8 = 0, 0));

do {
  let digest = Sha256.new(); // default algo #sha256 
  digest.writeBlob("hello");
  prt (digest.peekSum());
  digest.writeBlob(" world!");
  prt (digest.sum());
}
