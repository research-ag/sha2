import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Sha256 "../src/Sha256";

import Prim "mo:prim";

let chunk0 : Blob = "\89\50\4e\47\0d\0a\1a\0a\00\00\00\0d\49\48\44\52\00\00\0d\70\00\00\05\a0\08\06\00\00\00\4d\72\8a\c4";
let chunk1 : Blob = "\00\00\00\20\63\48\52\4d\00\00\7a\25\00\00\80\83\00\00\f9\ff\00\00\80\e9\00\00\75\30\00\00\ea\60\00";

let combined = Array.append(Blob.toArray(chunk0), Blob.toArray(chunk1)) |> Blob.fromArray(_);
let digest = Sha256.fromBlob(#sha256, combined);
Prim.debugPrint("Digest: " # debug_show (digest));

let digest2 = Sha256.Digest(#sha256);
digest2.writeIter(chunk0.vals());
digest2.writeIter(chunk1.vals());
let sum = digest2.sum();
Prim.debugPrint("Digest2: " # debug_show (sum));
assert Blob.equal(sum, digest);

let digest3 = Sha256.Digest(#sha256);
digest3.writeBlob(chunk0);
digest3.writeBlob(chunk1);
let sum2 = digest3.sum();
Prim.debugPrint("Digest3: " # debug_show (sum2));
assert Blob.equal(sum2, digest);
