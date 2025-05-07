package merkle

// Tree represents a Merkle tree.
type Tree struct {
	hasher    Hasher
	buf       []byte // Buffer for temporary storage of hashes
	minHeight int    // Minimum height of the tree

	base *layer // The base layer of the tree (the leafs)
}

// layer represents a layer in the Merkle tree.
type layer struct {
	parking []byte // The node that is pending for hashing, if any
	next    *layer // The next layer in the tree
}

// NodeSize returns the length of the hash used for the nodes in the tree.
func (t *Tree) NodeSize() int {
	return t.hasher.Size()
}

// Add adds a new value (leaf) to the tree.
func (t *Tree) Add(value []byte) {
	curNode := make([]byte, 0, len(value))
	curNode = append(curNode, value...)
	curLayer := t.base

	// Loop through the layers of the tree
	for {
		// If no node is pending, then this is a left sibling pending for its right sibling
		// before hashing for the parent
		if curLayer.parking == nil {
			curLayer.parking = curNode
			break
		}

		// If the parking node is not nil, then we have a right sibling
		root := t.hasher.Hash(t.buf, curLayer.parking, curNode)
		curNode = append(curNode[:0], root...)
		curLayer.parking = nil
		if curLayer.next == nil {
			// If there is no next layer, create a new one
			curLayer.next = &layer{}
		}
		curLayer = curLayer.next // Move to the next layer in the tree
	}
}

// Root returns the root hash of the tree.
func (t *Tree) Root() []byte {
	var root []byte
	padding := make([]byte, t.hasher.Size())
	height := -1
	for curLayer := t.base; curLayer != nil; curLayer = curLayer.next {
		height++
		switch {
		case curLayer.parking != nil && root == nil && curLayer.next == nil:
			// This is a balanced tree, so the parking node is the root
			root = curLayer.parking
		case curLayer.parking != nil && root != nil:
			// If there is a parking node and a root, hash them together
			root = t.hasher.Hash(nil, curLayer.parking, root)
		case curLayer.parking != nil:
			// If there is a parking node, but no root, hash it with the padding value
			root = t.hasher.Hash(nil, curLayer.parking, padding)
		case root != nil:
			// If there is a root, but no parking node, hash it with the padding value
			root = t.hasher.Hash(nil, root, padding)
		}
	}
	// If the height is less than the minimum height, add padding nodes
	for i := height; i < t.minHeight; i++ {
		root = t.hasher.Hash(nil, root, padding)
	}
	return root
}
