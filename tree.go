package merkle

import "math/bits"

// Tree represents a Merkle tree.
type Tree struct {
	hasher    Hasher
	buf       []byte // Buffer for temporary storage of hashes
	padding   []byte // Padding for the tree
	minHeight uint64 // Minimum height of the tree

	base *layer // The base layer of the tree (the leafs)

	currentLeaf   uint64   // The current leaf index
	leavesToProve []uint64 // leavesToProve is sorted set of indices of leaves to prove
	proof         [][]byte // The proof of the leaves to prove
}

// layer represents a layer in the Merkle tree.
type layer struct {
	parking       []byte // The node that is pending for hashing, if any
	onProvingPath bool   // Indicates if this layer is on the proving path

	next *layer // The next layer in the tree
}

// NodeSize returns the length of the hash used for the nodes in the tree.
func (t *Tree) NodeSize() int {
	return t.hasher.Size()
}

// Add adds a new value (leaf) to the tree.
func (t *Tree) Add(value []byte) {
	curNode := make([]byte, len(value))
	copy(curNode, value)
	curLayer := t.base

	onProvingPath := false
	if len(t.leavesToProve) > 0 && t.currentLeaf == t.leavesToProve[0] {
		onProvingPath = true
		t.leavesToProve = t.leavesToProve[1:]
	}
	t.currentLeaf++

	// Loop through the layers of the tree
	for {
		// If no node is pending, then this is a left sibling
		// add it as a parking node and keep information on if it is on the proving path
		if curLayer.parking == nil {
			curLayer.parking = curNode
			curLayer.onProvingPath = onProvingPath
			break
		}

		// If the parking node is not nil, then we have a right sibling

		// If the left or right child is on the proving path, we need to add the other child to the proof
		leftChildOnPath := curLayer.onProvingPath
		rightChildOnPath := onProvingPath
		switch {
		case leftChildOnPath && !rightChildOnPath:
			// add the right child (current node) to the proof
			proofNode := make([]byte, len(curNode))
			copy(proofNode, curNode)
			t.proof = append(t.proof, proofNode)
		case !leftChildOnPath && rightChildOnPath:
			// add the left child (parking node) to the proof
			proofNode := make([]byte, len(curLayer.parking))
			copy(proofNode, curLayer.parking)
			t.proof = append(t.proof, proofNode)
		default:
			// either both or none are on the proving path
			// do not add anything to the proof
		}

		// Hash the parking node (left child) and the current node (right child) together
		// store the result in the current node and move to the next layer
		root := t.hasher.Hash(t.buf, curLayer.parking, curNode)
		curNode = append(curNode[:0], root...)
		onProvingPath = leftChildOnPath || rightChildOnPath
		curLayer.parking = nil
		curLayer.onProvingPath = false
		if curLayer.next == nil {
			// If there is no next layer, create a new one
			curLayer.next = &layer{}
		}
		curLayer = curLayer.next // Move to the next layer in the tree
	}
}

// Root returns the root hash of the tree.
func (t *Tree) Root() []byte {
	root, _ := t.RootAndProof()
	return root
}

// RootAndProof returns the root hash and the proof for the leaves to prove.
func (t *Tree) RootAndProof() ([]byte, [][]byte) {
	var proof [][]byte
	if t.leavesToProve != nil {
		// Proof size is at least the minimum height of the tree either set by the user or
		// calculated from the current leaf. It can be bigger with multiple leaves to prove.
		// This sets a reasonable starting capacity for the proof slice to avoid many allocations.
		proofLen := max(int(t.minHeight), bits.Len64(t.currentLeaf), len(t.proof))
		proof = make([][]byte, len(t.proof), proofLen)
		for i, p := range t.proof {
			proof[i] = make([]byte, len(p))
			copy(proof[i], p)
		}
	}

	var root []byte
	height := -1
	onProvingPath := false
	for curLayer := t.base; curLayer != nil; curLayer = curLayer.next {
		height++
		// If this is a balanced tree, the parking node is the root and the proof is complete
		if curLayer.parking != nil && root == nil && curLayer.next == nil {
			root = curLayer.parking
			break
		}

		// Otherwise check if we are on the proving path and need to add one of the nodes to the proof
		switch {
		case curLayer.onProvingPath && !onProvingPath:
			proofNode := make([]byte, t.hasher.Size())
			copy(proofNode, root)
			proof = append(proof, proofNode)
			onProvingPath = true
		case onProvingPath && !curLayer.onProvingPath:
			proofNode := make([]byte, t.hasher.Size())
			copy(proofNode, curLayer.parking)
			proof = append(proof, proofNode)
		default:
			// either both or none are on the proving path, do not add anything to the proof
		}

		// In unbalanced trees walk up the layers by hashing the parking node and the current node together
		switch {
		case curLayer.parking != nil && root != nil:
			// If there is a parking node and a root, hash them together for the new root
			root = t.hasher.Hash(root, curLayer.parking, root)
		case curLayer.parking != nil:
			// If there is a parking node, but no root, hash it with the padding value
			root = t.hasher.Hash(root, curLayer.parking, t.padding)
		case root != nil:
			// If there is a root, but no parking node, hash it with the padding value
			root = t.hasher.Hash(root, root, t.padding)
		}
	}
	// If the height is less than the minimum height, add padding nodes
	for i := uint64(height); i < t.minHeight; i++ {
		root = t.hasher.Hash(root, root, t.padding)
		proof = append(proof, t.padding)
	}
	return root, proof
}
