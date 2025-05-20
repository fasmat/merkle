package merkle

import (
	"crypto/sha256"
	"hash"
	"sync"
)

// Hasher is an interface for calculating the parent node from two child nodes.
type Hasher interface {
	// Hash computes the hash of the given child hashes.
	// A buffer is provided to avoid allocations. Only write to the buffer after consuming the
	// children since it might point to the same memory as one of the child hashes.
	// Do not modify lChild and rChild in the process of hashing, since they might be still be used after the call.
	Hash(buf, lChild, rChild []byte) []byte

	// Size returns the size of the hash in bytes.
	Size() int
}

type sha256Hasher struct {
	pool *sync.Pool
}

func (sha256Hasher) Size() int {
	return sha256.Size
}

func (s *sha256Hasher) Hash(buf, lChild, rChild []byte) []byte {
	// Use the sync.Pool to get a hash.Hash instance. The cast is safe, since we control the pool
	h := s.pool.Get().(hash.Hash)
	defer s.pool.Put(h)
	defer h.Reset()

	h.Write(lChild)
	h.Write(rChild)
	return h.Sum(buf[:0])
}

// Sha256 returns a Hasher that computes the root by concatenating the two children and hashing them with SHA256.
// It uses a sync.Pool to reuse hash.Hash instances for efficiency while still allowing multiple trees to be built
// concurrently using the same underlying hasher.
func Sha256() Hasher {
	return &sha256Hasher{
		pool: &sync.Pool{
			New: func() any {
				return sha256.New()
			},
		},
	}
}

// LeafHasher is an interface for calculating the hash of the leaf from its data and its left siblings on the path to
// the root. This ensures that the merkle tree is built sequentially and parallelization of hashing is not possible,
// since to add a new leaf, all the previous leaves (and their parents) must be hashed first.
type LeafHasher interface {
	// Hash computes the hash of the leaf from its data and its left siblings on the path to the root.
	// A buffer is provided to avoid allocations.
	// Do not modify the data or the siblings in the process of hashing, since they might still be used after calling
	// this method.
	Hash(buf, data []byte, leftSiblings [][]byte) []byte

	// Size returns the size of the hash in bytes.
	Size() int
}

type valueLeafs struct {
	size int
}

func (v *valueLeafs) Size() int {
	return v.size
}

func (valueLeafs) Hash(buf, data []byte, _ [][]byte) []byte {
	buf = append(buf[:0], data...)
	return buf
}

// ValueLeafs returns a LeafHasher that uses the added value as leaf hash. This is useful when the leaves are already
// hashes and you want to use them as is in the tree.
//
// The LeafHasher will copy the data passed to Add(). For this uses a buffer of the given size. You can specify the
// size of the buffer that is used. To avoid unnecessary re-allocations it should be large enough to hold any leaf you
// want to add.
func ValueLeafs(size int) LeafHasher {
	return &valueLeafs{
		size: size,
	}
}

type sequentialWorkHasher struct {
	pool *sync.Pool
}

func (sequentialWorkHasher) Size() int {
	return sha256.Size
}

func (s *sequentialWorkHasher) Hash(buf, data []byte, parkingNodes [][]byte) []byte {
	// Use the sync.Pool to get a hash.Hash instance. The cast is safe, since we control the pool
	h := s.pool.Get().(hash.Hash)
	defer s.pool.Put(h)
	defer h.Reset()

	h.Write(data)
	for i := range parkingNodes {
		h.Write(parkingNodes[i])
	}
	return h.Sum(buf[:0])
}

// SequentialWorkHasher returns a LeafHasher that computes the leaf hash by concatenating the data and the parking nodes
// and hashing them with SHA256. It uses a sync.Pool to reuse hash.Hash instances for efficiency while still allowing
// multiple trees to be built concurrently using the same underlying hasher.
func SequentialWorkHasher() LeafHasher {
	return &sequentialWorkHasher{
		pool: &sync.Pool{
			New: func() any {
				return sha256.New()
			},
		},
	}
}
