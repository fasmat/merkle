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
	hasher Hasher
}

func (v *validatorOpts) Hasher() Hasher {
	if v.hasher == nil {
		v.hasher = Sha256()
	}
	return v.hasher
}

// ValidatorOpt is a functional option for configuring the validator.
type ValidatorOpt func(*validatorOpts)

// WithHasher sets the hash function for the validator.
func WithHasher(f Hasher) ValidatorOpt {
	return func(opts *validatorOpts) {
		opts.hasher = f
	}
}

// ValidateProof validates a Merkle tree proof against the provided root and leaves.
func ValidateProof(root []byte, leaves map[uint64][]byte, proof [][]byte, opts ...ValidatorOpt) (bool, error) {
	validatorOpts := &validatorOpts{}
	for _, opt := range opts {
		opt(validatorOpts)
	}

	if len(root) != validatorOpts.Hasher().Size() {
		return false, errors.New("invalid root size")
	}
	if len(leaves) == 0 {
		return false, ErrNoLeaves
	}

	indices := slices.Collect(maps.Keys(leaves))
	slices.Sort(indices)
	v := &validator{
		hasher: validatorOpts.Hasher(),

		leaves:  leaves,
		indices: indices,
		proof:   proof,
	}

	calculatedRoot, err := v.calcRoot(math.MaxUint64)
	if err != nil {
		return false, err
	}
	return bytes.Equal(root, calculatedRoot), nil
}

type validator struct {
	hasher Hasher

	leaves  map[uint64][]byte
	indices []uint64
	proof   [][]byte
}

func (v *validator) calcRoot(maxHeight uint64) ([]byte, error) {
	currIndex := v.indices[0]
	v.indices = v.indices[1:]
	currNode := v.leaves[currIndex]

	var lChild, rChild []byte
	buf := make([]byte, v.hasher.Size())

	for height := range maxHeight {
		switch {
		case len(v.proof) == 0 && len(v.indices) == 0: // no more to prove
			return currNode, nil
		case len(v.indices) > 0 && v.indices[0]>>height == currIndex^1:
			// next index is an ancestor of the sibling of the current node
			// we need to calculate the sibling first by calculating the root of the subtree
			sibling, err := v.calcRoot(height)
			if err != nil {
				return nil, err
			}
			if currIndex%2 == 0 {
				lChild, rChild = currNode, sibling
			} else {
				lChild, rChild = sibling, currNode
			}
		default: // next index is not an ancestor of the sibling of the current node
			if len(v.proof) == 0 {
				return nil, ErrShortProof
			}
			if currIndex%2 == 0 {
				lChild, rChild = currNode, v.proof[0]
			} else {
				lChild, rChild = v.proof[0], currNode
			}
			v.proof = v.proof[1:]
		}

		// we are moving up the tree, the index of the current node on the new hight is half of the current index
		currIndex >>= 1
		currNode = v.hasher.Hash(buf, lChild, rChild)
	}

	// we reached the root of the tree with the given max height
	return currNode, nil
}
