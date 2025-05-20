package merkle

import "math/bits"

// Tree represents a Merkle tree.
type Tree struct {
	hasher Hasher

	buf     []byte // Buffer for temporary storage of hashes
	padding []byte // Padding for the tree

	minHeight     uint64   // Minimum height of the tree
	leavesToProve []uint64 // leavesToProve is sorted set of indices of leaves to prove

	parkedNodes   [][]byte // The parked nodes of the tree
	onProvingPath []bool   // Indicates if the parked nodes are on the proving path
	currentLeaf   uint64   // The current leaf index
	proof         [][]byte // The proof of the leaves to prove
}

// NodeSize returns the length of the hash used for the nodes in the tree.
func (t *Tree) NodeSize() int {
	return t.hasher.Size()
}

// Add adds a new value (leaf) to the tree.
//
// Call this method for each leaf you want to add to the tree before retrieving the root hash with Root() or
// RootAndProof().
func (t *Tree) Add(value []byte) {
	curNode := make([]byte, len(value))
	copy(curNode, value)

	// If needed, check if the current leaf is on the proving path
	curOnProvingPath := false
	if len(t.leavesToProve) > 0 && t.currentLeaf == t.leavesToProve[0] {
		curOnProvingPath = true
		t.leavesToProve = t.leavesToProve[1:]
	}
	t.currentLeaf++

	// Loop through the layers (parked nodes) of the tree
	for height := 0; ; height++ {
		// If there is no layer at current height, add one
		if height == len(t.parkedNodes) {
			t.parkedNodes = append(t.parkedNodes, nil)
			t.onProvingPath = append(t.onProvingPath, false)
		}
		parkingNode := &t.parkedNodes[height]
		parkingOnProvingPath := &t.onProvingPath[height]

		// If no node is parking, then the current node is a left sibling
		// add it as the parking node and keep information on it being on the proving path or not
		if *parkingNode == nil {
			*parkingNode = curNode
			*parkingOnProvingPath = curOnProvingPath
			break
		}

		// If the parking node is not nil, then the current node is a right sibling
		switch {
		case *parkingOnProvingPath && !curOnProvingPath:
			// add the right child (current node) to the proof
			proofNode := make([]byte, len(curNode))
			copy(proofNode, curNode)
			t.proof = append(t.proof, proofNode)
		case !*parkingOnProvingPath && curOnProvingPath:
			// add the left child (parking node) to the proof
			proofNode := make([]byte, len(*parkingNode))
			copy(proofNode, *parkingNode)
			t.proof = append(t.proof, proofNode)
		default:
			// either both or none are on the proving path
			// do not add anything to the proof
		}

		// Hash the parking node (left child) and the current node (right child) together
		// store the result in the current node and move to the next layer
		root := t.hasher.Hash(t.buf, *parkingNode, curNode)
		curNode = append(curNode[:0], root...)
		curOnProvingPath = *parkingOnProvingPath || curOnProvingPath
		*parkingNode = nil
		*parkingOnProvingPath = false
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
		proofLen := max(int(t.minHeight), bits.Len64(t.currentLeaf)-1, len(t.proof))
		proof = make([][]byte, len(t.proof), proofLen)
		for i, p := range t.proof {
			proof[i] = make([]byte, len(p))
			copy(proof[i], p)
		}
	}

	var root []byte
	onProvingPath := false
	for height, parkedNode := range t.parkedNodes {
		// If this is a balanced tree, the parking node is the root and the proof is complete
		if parkedNode != nil && root == nil && height == len(t.parkedNodes)-1 {
			root = append(root[:0], parkedNode...) // Copy the parking node to the root
			break
		}

		// Otherwise check if we are on the proving path and need to add one of the nodes to the proof
		switch {
		case t.onProvingPath[height] && !onProvingPath:
			proofNode := make([]byte, t.hasher.Size())
			copy(proofNode, root)
			proof = append(proof, proofNode)
			onProvingPath = true
		case onProvingPath && !t.onProvingPath[height]:
			proofNode := make([]byte, t.hasher.Size())
			copy(proofNode, parkedNode)
			proof = append(proof, proofNode)
		default:
			// either both or none are on the proving path, do not add anything to the proof
		}

		// In unbalanced trees walk up the layers by hashing the current root and parking node and use as new root
		// If either is nil, use the padding value instead
		// If both are nil continue with next layer
		switch {
		case parkedNode != nil && root != nil:
			root = t.hasher.Hash(root, parkedNode, root)
		case parkedNode != nil:
			root = t.hasher.Hash(root, parkedNode, t.padding)
		case root != nil:
			root = t.hasher.Hash(root, root, t.padding)
		}
	}
	// If the height is less than the minimum height, add padding nodes
	for i := uint64(len(t.parkedNodes)); i < t.minHeight; i++ {
		root = t.hasher.Hash(root, root, t.padding)
		proof = append(proof, t.padding)
	}
	return root, proof
}
