# Sha2 changelog

## 0.1.0

* Add share/unshare interface to Digest classes 

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

