package merkle

import (
	"bytes"
	"errors"
	"maps"
	"math"
	"math/bits"
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
	if err := v.initParkingNodes(); err != nil {
		return false, err
	}

	buf := make([]byte, 0, v.leafHasher.Size())
	calculatedRoot, err := v.calcRoot(math.MaxUint64, buf)
	if err != nil {
		return false, err
	}
	return bytes.Equal(root, calculatedRoot), nil
}

type validator struct {
	hasher     Hasher
	leafHasher LeafHasher

	leaves      map[uint64][]byte
	indices     []uint64
	parkedNodes map[uint64][][]byte
	proof       [][]byte
}

func (v *validator) initParkingNodes() error {
	if !v.leafHasher.Sequential() {
		return nil
	}

	// the tree hight based on the highest index - the actual tree might be higher
	// for parked nodes we only need the height of the subtree containing the proven leaves
	treeHeight := bits.Len64(v.indices[len(v.indices)-1])

	// we preallocate parked nodes for all indices with a length of the calculated tree height
	// this avoids unnecessary allocations when we park the nodes
	v.parkedNodes = make(map[uint64][][]byte, len(v.indices))

	for idx := range v.indices {
		parkedNodes := make([][]byte, treeHeight)
		if len(parkedNodes) > 0 {
			parkedNodes[0] = make([]byte, 0, v.leafHasher.Size())
		}
		for i := 1; i < len(parkedNodes); i++ {
			parkedNodes[i] = make([]byte, 0, v.hasher.Size())
		}
		v.parkedNodes[v.indices[idx]] = parkedNodes
	}

	_, _, err := v.parkingNodes(uint64(treeHeight), v.indices, v.proof)
	return err
}

// parkingNodes returns the parking nodes from the proof for the current subtree with the given max height.
func (v *validator) parkingNodes(maxHeight uint64, indices []uint64, proof [][]byte) (uint64, int, error) {
	proofIdx := uint64(0)
	curIndex := indices[0]
	curParkedNodes := v.parkedNodes[curIndex]
	indices = indices[1:]
	siblingIdx := 0
	for height := range maxHeight {
		switch {
		// the subtree with the current height is a left sibling and
		// the next leaf is part of the subtree forming the right sibling
		case curIndex&1 == 0 && siblingIdx < len(indices) && (indices[siblingIdx]>>height) == (curIndex^1):
			curParkedNodes[height] = curParkedNodes[height][:0]
			proofLen, siblingLen, err := v.parkingNodes(height, indices[siblingIdx:], proof[proofIdx:])
			if err != nil {
				return proofIdx, siblingIdx, err
			}
			proofIdx += proofLen
			siblingIdx += 1 + siblingLen // consumed one sibling directly plus `siblingLen` recursively

		// the subtree with the current height is a left sibling and
		// the subtree forming the right sibling is not part of the proof
		case curIndex&1 == 0:
			curParkedNodes[height] = curParkedNodes[height][:0]
			proofIdx++

		// the subtree with the current height is a right sibling
		// so the proof at this height contains the left sibling which we need as the parked node
		case curIndex&1 == 1:
			if proofIdx >= uint64(len(v.proof)) {
				// if we are missing proof nodes we can't calculate
				return proofIdx, siblingIdx, ErrShortProof
			}
			curParkedNodes[height] = append(curParkedNodes[height][:0], proof[proofIdx]...)
			proofIdx++
		}

		curIndex >>= 1
	}
	return proofIdx, siblingIdx, nil
}

// calcRoot calculates the root of the Merkle tree using the provided leaves and proof.
// It is called recursively to traverse subtrees of siblings if needed and consumes
// the proof as it goes.
// The maxHeight parameter is used to determine the maximum height of the (sub-)tree
// to be calculated. RootBuf is used to store the current root value and is reused
// to avoid unnecessary allocations.
func (v *validator) calcRoot(maxHeight uint64, rootBuf []byte) ([]byte, error) {
	curIndex := v.indices[0]
	curParkedNodes := v.parkedNodes[curIndex]
	v.indices = v.indices[1:]
	curNode := v.leafHasher.Hash(rootBuf, v.leaves[curIndex], curParkedNodes)

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

			v.copyParkedNodes(height, curNode, curParkedNodes)
			sibling, err := v.calcRoot(height, siblingBuf)
			if err != nil {
				return nil, err
			}
			lChild, rChild = curNode, sibling
		default: // next index is not an ancestor of the sibling of the current node
			if len(v.proof) == 0 {
				return nil, ErrShortProof
			}
			if curIndex&1 == 0 {
				lChild, rChild = curNode, v.proof[0]
			} else {
				lChild, rChild = v.proof[0], curNode
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

// copyParkedNodes sets the parked nodes for the next index in the proof to the same as for the current index
// starting from the given height.
func (v *validator) copyParkedNodes(height uint64, curNode []byte, curParkedNodes [][]byte) {
	if !v.leafHasher.Sequential() {
		return
	}

	// the current node at the current height is the left sibling of the subtree we will process
	// so it is a parked node for the right sibling at the current height
	v.parkedNodes[v.indices[0]][height] = append(v.parkedNodes[v.indices[0]][height][:0], curNode...)

	// all parked nodes at higher heights of the current node are parked for the right sibling as well
	for i := height + 1; i < uint64(len(curParkedNodes)); i++ {
		v.parkedNodes[v.indices[0]][i] = append(v.parkedNodes[v.indices[0]][i][:0], curParkedNodes[i]...)
	}
}
