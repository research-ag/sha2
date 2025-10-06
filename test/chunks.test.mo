import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Sha256 "../src/Sha256";
import Sha512 "../src/Sha512";

import Prim "mo:prim";

do {
  Prim.debugPrint("SHA 256 test");

  let chunk0 : Blob = "\89\50\4e\47\0d\0a\1a\0a\00\00\00\0d\49\48\44\52\00\00\0d\70\00\00\05\a0\08\06\00\00\00\4d\72\8a\c4";
  let chunk1 : Blob = "\00\00\00\20\63\48\52\4d\00\00\7a\25\00\00\80\83\00\00\f9\ff\00\00\80\e9\00\00\75\30\00\00\ea\60\00";
  let combined = Array.concat(Blob.toArray(chunk0), Blob.toArray(chunk1));

  let digest = Sha256.fromArray(#sha256, combined);
  Prim.debugPrint("Digest: " # debug_show (digest));

  let digest2 = Sha256.new(#sha256);
  digest2.writeIter(chunk0.vals());
  digest2.writeIter(chunk1.vals());
  let sum = digest2.sum();
  Prim.debugPrint("Digest2: " # debug_show (sum));
  assert Blob.equal(sum, digest);

  let digest3 = Sha256.new(#sha256);
  digest3.writeBlob(chunk0);
  digest3.writeBlob(chunk1);
  let sum2 = digest3.sum();
  Prim.debugPrint("Digest3: " # debug_show (sum2));
  assert Blob.equal(sum2, digest);
};

do {
  Prim.debugPrint("SHA 512 test");

  let chunk0 : Blob = "\89\50\4e\47\0d\0a\1a\0a\00\00\00\0d\49\48\44\52\00\00\0d\70\00\00\05\a0\08\06\00\00\00\4d\72\8a\c4\00\00\00\20\63\48\52\4d\00\00\7a\25\00\00\80\83\00\00\f9\ff\00\00\80\e9\00\00\75\30\00\00\ea\60";
  let chunk1 : Blob = "\00\00\3a\98\00\00\17\6f\92\5f\c5\46\00\30\fd\d5\49\44\41\54\78\da\dc\fd\5b\96\25\b9\aa\04\8a\02\1e\ab\bb\a7\03\b7\db\f7\af\c2\e1\7c\08\49\06\42\ee\3e\1f\99\55\fb\e4\1e\b5\57\3e\22\62\fa\43\42\60";
  let combined = Array.concat(Blob.toArray(chunk0), Blob.toArray(chunk1));

  let digest = Sha512.fromArray(#sha512, combined);
  Prim.debugPrint("Digest: " # debug_show (digest));

  let digest2 = Sha512.new(#sha512);
  digest2.writeIter(chunk0.vals());
  digest2.writeIter(chunk1.vals());
  let sum = digest2.sum();
  Prim.debugPrint("Digest2: " # debug_show (sum));
  assert Blob.equal(sum, digest);

  let digest3 = Sha512.new(#sha512);
  digest3.writeBlob(chunk0);
  digest3.writeBlob(chunk1);
  let sum2 = digest3.sum();
  Prim.debugPrint("Digest3: " # debug_show (sum2));
  assert Blob.equal(sum2, digest);
};
