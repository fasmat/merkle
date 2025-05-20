package merkle

import (
	"maps"
	"slices"
)

// Builder is a builder for creating a Merkle tree. Use it with TreeBuilder() and With...() methods.
type Builder struct {
	hasher        Hasher
	leafHasher    LeafHasher
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

// WithLeafHasher sets the hash function for the leaves of the Merkle tree. If not set, the leafs are used as is.
// It can be used when some form of Proof of Sequential Work (PoSW) is needed when building the tree. For details
// see the LeafHasher interface.
//
// If no Proof of Sequential Work is needed it is recommended to either add the leaves as is or manually hash them
// before adding them to the tree.
func (tb *Builder) WithLeafHasher(h LeafHasher) *Builder {
	tb.leafHasher = h
	return tb
}

// WithMinHeight sets the minimum height for the Merkle tree.
func (tb *Builder) WithMinHeight(h uint64) *Builder {
	tb.minHeight = h
	return tb
}

// WithLeafToProve sets a leaf a merkle proof should be generated for.
// Can be called multiple times. The proof will be generated for the union of all leaves, overwriting previous ones.
// For an example see the WithLeavesToProve method.
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

	if tb.leafHasher == nil {
		// If the leaf hasher is not set, use the values as leaves directly and assume they are
		// the same size as the hasher.
		tb.leafHasher = ValueLeafs(tb.hasher.Size())
	}

	indices := slices.Collect(maps.Keys(tb.leavesToProve))
	slices.Sort(indices)
	tree := &Tree{
		hasher:     tb.hasher,
		leafHasher: tb.leafHasher,

		buf:     make([]byte, tb.hasher.Size()),
		leafBuf: make([]byte, tb.leafHasher.Size()),
		padding: make([]byte, tb.hasher.Size()),

		minHeight:     tb.minHeight,
		leavesToProve: indices,
	}
	return tree
}
