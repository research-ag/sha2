/// Cycle-optimized Sha512 variants.
///
/// Features:
///
/// * Algorithms: `sha512_224`, `sha512_256`, `sha384`, `sha512`
/// * Input types: `Blob`, `[Nat8]`, `Iter<Nat8>`
/// * Output types: `Blob`

import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Prim "mo:prim";

import StaticSha512 "Static";

module {

  public type Algorithm = StaticSha512.Algorithm;

  public class Digest(algo_ : Algorithm) {
    let state = StaticSha512.Digest(algo_);

    public func algo() : Algorithm = algo_;

    public func reset() = StaticSha512.reset(state);

    reset();

    public func writeIter(iter : { next() : ?Nat8 }) = StaticSha512.writeIter(state, iter);

    public func writeArray(arr : [Nat8]) : () = StaticSha512.writeIter(state, arr.vals());
    public func writeBlob(blob : Blob) : () = StaticSha512.writeIter(state, blob.vals());

    public func sum() : Blob = StaticSha512.sum(state);
  }; // class Digest

  // Calculate SHA256 hash digest from [Nat8].
  public func fromArray(algo : Algorithm, arr : [Nat8]) : Blob {
    let digest = Digest(algo);
    digest.writeIter(arr.vals());
    return digest.sum();
  };

  // Calculate SHA2 hash digest from Iter.
  public func fromIter(algo : Algorithm, iter : { next() : ?Nat8 }) : Blob {
    let digest = Digest(algo);
    digest.writeIter(iter);
    return digest.sum();
  };

  // Calculate SHA2 hash digest from Blob.
  public func fromBlob(algo : Algorithm, b : Blob) : Blob {
    let digest = Digest(algo);
    digest.writeIter(b.vals());
    return digest.sum();
  };
};
