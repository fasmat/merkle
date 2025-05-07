package merkle

// Builder is a builder for creating a Merkle tree. Use it with TreeBuilder() and With...() methods.
type Builder struct {
	hasher    Hasher
	minHeight int
}

// NewTree creates a new Merkle tree with the default hash function (SHA256).
func NewTree() *Tree {
	return TreeBuilder().Build()
}

// TreeBuilder creates a new builder for a Merkle tree.
func TreeBuilder() Builder {
	return Builder{}
}

// WithHasher sets the hash function for the Merkle tree.
func (tb Builder) WithHasher(f Hasher) Builder {
	tb.hasher = f
	return tb
}

// WithMinHeight sets the minimum height for the Merkle tree.
func (tb Builder) WithMinHeight(h int) Builder {
	tb.minHeight = h
	return tb
}

// Build constructs the Merkle tree with the specified properties.
func (tb Builder) Build() *Tree {
	if tb.hasher == nil {
		tb.hasher = Sha256()
	}
	tree := &Tree{
		hasher:    tb.hasher,
		buf:       make([]byte, tb.hasher.Size()),
		minHeight: tb.minHeight,

		base: &layer{},
	}
	return tree
}
