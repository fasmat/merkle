package merkle

import (
	"crypto/sha256"
	"hash"
	"sync"
)

// Hasher is an interface for hashing two child hashes to compute a parent hash.
type Hasher interface {
	// Hash computes the hash of the given child hashes.
	// A buffer is provided to avoid allocations. Only write to the buffer after consuming the
	// children since it might point to the same memory as one of the child hashes.
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
	h := s.pool.Get().(hash.Hash) //nolint:errcheck
	defer s.pool.Put(h)
	defer h.Reset()

	h.Write(lChild)
	h.Write(rChild)
	return h.Sum(buf[:0])
}

// Sha256 returns a Hasher that computes the root by concatenating the two children and hashing them with SHA256.
// It uses a sync.Pool to reuse hash.Hash instances for efficiency while still allowing multiple trees to be built
// concurrently using the same hasher.
func Sha256() Hasher {
	return &sha256Hasher{
		pool: &sync.Pool{
			New: func() any {
				return sha256.New()
			},
		},
	}
}
