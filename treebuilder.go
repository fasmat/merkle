package merkle

import (
	"maps"
	"slices"
)

// Builder is a builder for creating a Merkle tree. Use it with TreeBuilder() and With...() methods.
type Builder struct {
	hasher        Hasher
	minHeight     uint64
	leavesToProve map[uint64]struct{}
}

// NewTree creates a new Merkle tree with the default hash function (SHA256).
func NewTree() *Tree {
	return TreeBuilder().Build()
}

// TreeBuilder creates a new builder for a Merkle tree.
func TreeBuilder() *Builder {
	return &Builder{
		leavesToProve: make(map[uint64]struct{}),
	}
}

// WithHasher sets the hash function for the Merkle tree. If not set, the default SHA256 hasher is used.
func (tb *Builder) WithHasher(h Hasher) *Builder {
	tb.hasher = h
	return tb
}

// WithMinHeight sets the minimum height for the Merkle tree.
func (tb *Builder) WithMinHeight(h uint64) *Builder {
	tb.minHeight = h
	return tb
}

// WithLeafToProve sets a leaf a merkle proof should be generated for.
// Can be called multiple times. The proof will be generated for the union of all leaves, overwriting previous ones.
func (tb *Builder) WithLeafToProve(leaf uint64) *Builder {
	tb.leavesToProve[leaf] = struct{}{}
	return tb
}

// WithLeavesToProve sets the leaves a merkle proof should be generated for.
// Can be called multiple times. The proof will be generated for the union of all leaves, overwriting previous ones.
func (tb *Builder) WithLeavesToProve(leaves map[uint64]struct{}) *Builder {
	maps.Copy(tb.leavesToProve, leaves)
	return tb
}

// Build constructs the Merkle tree with the specified properties.
func (tb *Builder) Build() *Tree {
	if tb.hasher == nil {
		tb.hasher = Sha256()
	}

	indices := slices.Collect(maps.Keys(tb.leavesToProve))
	slices.Sort(indices)
	tree := &Tree{
		hasher:    tb.hasher,
		buf:       make([]byte, tb.hasher.Size()),
		padding:   make([]byte, tb.hasher.Size()),
		minHeight: tb.minHeight,

		base:          &layer{},
		leavesToProve: indices,
	}
	return tree
}
