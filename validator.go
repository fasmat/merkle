package merkle

import (
	"bytes"
	"errors"
	"maps"
	"math"
	"slices"
)

var (
	// ErrShortProof is returned when the proof is too short to validate the leaves.
	ErrShortProof = errors.New("proof is too short")

	// ErrNoLeaves is returned when there are no leaves to prove.
	ErrNoLeaves = errors.New("no leaves to prove")
)

type validatorOpts struct {
	hasher     Hasher
	leafHasher LeafHasher
}

func (v *validatorOpts) Hasher() Hasher {
	if v.hasher == nil {
		v.hasher = Sha256()
	}
	return v.hasher
}

func (v *validatorOpts) LeafHasher() LeafHasher {
	if v.leafHasher == nil {
		v.leafHasher = ValueLeafs(v.Hasher().Size())
	}
	return v.leafHasher
}

// ValidatorOpt is a functional option for configuring the validator.
type ValidatorOpt func(*validatorOpts)

// WithHasher sets the hash function for the validator. If not set, the default SHA256 hasher is used.
func WithHasher(h Hasher) ValidatorOpt {
	return func(opts *validatorOpts) {
		opts.hasher = h
	}
}

// WithLeafHasher sets the hash function for the leaves of the Merkle tree. If not set, the leafs are used as is.
// It can be used when some form of Proof of Sequential Work (PoSW) is needed when building the tree. For details
// see the LeafHasher interface.
//
// If no Proof of Sequential Work is needed it is recommended to either add the leaves as is or manually hash them
// before adding them to the tree.
func WithLeafHasher(h LeafHasher) ValidatorOpt {
	return func(opts *validatorOpts) {
		opts.leafHasher = h
	}
}

// ValidateProof validates a Merkle tree proof against the provided root and leaves.
func ValidateProof(root []byte, leaves map[uint64][]byte, proof [][]byte, opts ...ValidatorOpt) (bool, error) {
	validatorOpts := &validatorOpts{}
	for _, opt := range opts {
		opt(validatorOpts)
	}

	if len(leaves) == 0 {
		return false, ErrNoLeaves
	}

	indices := slices.Collect(maps.Keys(leaves))
	slices.Sort(indices)
	v := &validator{
		hasher:     validatorOpts.Hasher(),
		leafHasher: validatorOpts.LeafHasher(),

		leaves:  leaves,
		indices: indices,
		proof:   proof,
	}

	buf := make([]byte, 0, v.leafHasher.Size())
	calculatedRoot, err := v.calcRoot(math.MaxUint64, buf, nil)
	if err != nil {
		return false, err
	}
	return bytes.Equal(root, calculatedRoot), nil
}

type validator struct {
	hasher     Hasher
	leafHasher LeafHasher

	leaves  map[uint64][]byte
	indices []uint64
	proof   [][]byte
}

// parkingNodes returns the parking nodes from the proof for the current subtree with the given max height.
func (v *validator) parkingNodes(maxHeight uint64) [][]byte {
	var parkingNodes [][]byte
	for height := range maxHeight {
		curIndex := v.indices[0] >> height
		if curIndex == 0 {
			// from here on out going up the tree we are always a left sibling
			return parkingNodes
		}
		if int(height) >= len(v.proof) {
			// this either means that we are missing proof nodes or that those will be calculated
			// by the calcRoot method, either way it's handled there
			return nil
		}
		if curIndex&1 == 1 {
			// the subtree with the current hight is a right sibling
			// so the proof at this height contains the left sibling (the parking node)
			parkingNodes = append(parkingNodes, v.proof[height])
		}
	}
	return parkingNodes
}

// calcRoot calculates the root of the Merkle tree using the provided leaves and proof.
// It is called recursively to traverse subtrees of siblings if needed and consumes
// the proof as it goes.
// The maxHeight parameter is used to determine the maximum height of the (sub-)tree
// to be calculated. RootBuf is used to store the current root value and is reused
// to avoid unnecessary allocations.
func (v *validator) calcRoot(maxHeight uint64, rootBuf []byte, parkingNodes [][]byte) ([]byte, error) {
	parkingNodes = append(v.parkingNodes(maxHeight), parkingNodes...)
	curIndex := v.indices[0]
	v.indices = v.indices[1:]
	curNode := v.leafHasher.Hash(rootBuf, v.leaves[curIndex], parkingNodes)

	var lChild, rChild []byte
	var siblingBuf []byte

	for height := range maxHeight {
		switch {
		case len(v.proof) == 0 && len(v.indices) == 0: // no more to prove
			if curIndex != 0 {
				// if we reached the root curIndex should be 0, if it isn't we are missing proof nodes
				return nil, ErrShortProof
			}
			return curNode, nil
		case len(v.indices) > 0 && (v.indices[0]>>height) == (curIndex^1):
			// next index is an ancestor of the right sibling of the current node
			// we need to calculate the sibling first by calculating the root of the subtree
			if siblingBuf == nil {
				siblingBuf = make([]byte, v.hasher.Size())
			}

			// the current node is the left sibling of the subtree we will process
			// so it is a parking node for all leafs in the subtree and we need to copy it
			node := make([]byte, len(curNode))
			copy(node, curNode)
			parkingNodes = append([][]byte{node}, parkingNodes...)

			sibling, err := v.calcRoot(height, siblingBuf, parkingNodes)
			if err != nil {
				return nil, err
			}
			lChild, rChild = curNode, sibling

			parkingNodes = parkingNodes[1:] // we move up one layer as the right sibling
		default: // next index is not an ancestor of the sibling of the current node
			if len(v.proof) == 0 {
				return nil, ErrShortProof
			}
			if curIndex&1 == 0 {
				lChild, rChild = curNode, v.proof[0]
			} else {
				lChild, rChild = v.proof[0], curNode
				if len(parkingNodes) > 0 {
					parkingNodes = parkingNodes[1:] // we move up one layer as the right sibling
				}
			}
			v.proof = v.proof[1:]
		}

		// we are moving up the tree, the index of the current node on the new height is half of the current index
		curIndex >>= 1
		curNode = v.hasher.Hash(curNode, lChild, rChild)
	}

	// we reached the root of the tree with the given max height
	return curNode, nil
}
