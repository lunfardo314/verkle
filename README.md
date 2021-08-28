# 257-ary _verkle_ trie

_Disclaimer: the code in this package is experimental. It can only be used in research and not suitable for use in production.  
The _trusted setup_ must be created in a secure environment. This is a responsibility of the user.
The security of your trusted setup entirely depends on how you use the _kzg_setup_ program, i.e. how you treat the secret it is based upon._

## General
The repository contains an **experimental** implementation of the so-called [_verkle tree_](https://math.mit.edu/research/highschool/primes/materials/2018/Kuszmaul.pdf) as a 257-ary [trie](https://en.wikipedia.org/wiki/Trie), a prefix tree.

The implementation uses _polynomial KZG (aka Kate) commitments_ for _vector commitments_ instead of hashing
as a commitment method used in [Merkle trees](https://en.wikipedia.org/wiki/Merkle_tree).
The approach offers significant advantages with regard to performance, specifically data size of data structures.
Please find below references to the extensive literature about _KZG commitments_ and _verkle trees_.

The implementation uses _trusted setup_ completely in Lagrange basis.
Please find here all [math and formulas](https://hackmd.io/@Evaldas/SJ9KHoDJF) as well as references to articles it is based upon.

The implementation uses a bit unconventional approach to the data structure of the trie, the _257-ary trie_.
The rationale for this is always use original keys of arbitrary length without hashing them as in Patricia tries.
Any key can point to the terminal value and be a prefix in other keys.
So, in each node, we need to commit to up to `256` children (max byte value) plus, possibly, to one terminal value, hence `257`.

We see benefits in the approach, due to its properties:

* the trie is wide, so proofs are short.
* use of bytes as child indices makes encoding simpler than in _hexary Patricia trie_.
* keys used in the trie are short
* nodes are reused for commitments to terminal values
* keys are not randomized by hashing, so it represents structure of the state on the chain.
  It makes it possible, for example, to have commitments to partitions of state, say state of one smart contract
  or even one data structure in the state, say an array of a dictionary.
* adding to or updating a key/value pair never deletes keys from the trie, only updates
  a small amount of values and/or adds one new key/value pair.

As it is seen from the implementation, use of 257 instead of more conventional 256 trie does not add any significant overhead.

## Repository and dependencies

The repository contains:
- `kzg` package with the implementation of the _KZG commitments_ and the _trusted setup_.
- `kzg_setup`, the CLI program to create _trusted setups_ and store them into the file.
- `trie` package which contains implementation of the _257-ary trie_ as well as corresponding tests and benchmarks.

The implementation of _KZG commitments_ uses [DEDIS Advanced Crypto Library for Go Kyber v3](https://github.com/dedis/kyber)
and its `bn256` bilinear pairing suite as cryptographic primitives.
The implementation follows formulas presented [in this article](https://hackmd.io/@Evaldas/SJ9KHoDJF).

## Implementation

### The state
The state is assumed to be an arbitrary collection of the key/value pairs.
Empty key (`nil` or `""`) in the implementation is a valid key. The state assumes the empty key always contains  
serialized binary value of the _trusted setup_.

**Determinism of the state**: the state is a set of key/value pairs, i.e. no matter the order of how those key/value pairs were
added to the storage and trie, the state (and the commitment to it) is the same.

The key/value store is and impementation of `trie.KVStore` interface.

The state is implemented as `trie.State`. It contains partitions for values, for the trie itself, also cache
for keeping nodes being during bulky state update operations.

### The trie

The trie is represented as a collection of key/value pairs in the `trie` partition of the state. Each key/value pair in the trie
represents a _node_ of the trie in serialized form.

``` Go
// Node is a node of the 257-ary verkle trie
type Node struct {
	pathFragment  []byte
	children      [256]kyber.Point
	terminalValue kyber.Scalar
}
```
