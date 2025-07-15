# Sha2 changelog

##

* Bugfix in writeBlob/writeArray. Note: fromBlob/fromArray were correct, but calling the low-level writeBlob/writeArray multiple times could cause an error.

## 0.1.4

* Improve performance for short messages by 8%/12%
* Utilise explodeNatX functions from moc 0.14.9

## 0.1.3

* Improve performance by 35-40%
* Utilise Blob random access from moc 0.14.8

## 0.1.2

* Improve performance by 10-12%
* Utilise Blob random access from moc 0.14.8

## 0.1.1

* Introduce mops benchmarks
* Remove comparison to other packages from README
* Bump dependencies

## 0.1.0

* Add share/unshare interface to Digest classes 
* Bump base dependency

## 0.0.6

* Bump base and test dependencies
* Add benchmarks

## 0.0.5

* Bump base dependency to 0.11.0

## 0.0.4

Sha256:

* Eliminate the heap allocations that were linear in message size
* Reduce instructions per byte by 4%  
* Comes with a per message penalty in instructions of 5% 

## 0.0.3

Sha256:

* Reduce instructions per byte by 3%
* Reduce instructions for empty message by 25%
* Reduce heap allocations from 1.5x to 1x the message size

Sha512:

* Reduce instructions per byte by 3%
* Reduce instructions for empty message by 35%

