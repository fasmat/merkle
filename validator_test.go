package merkle_test

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/fasmat/merkle"
)

func ExampleValidateProof() {
	// Create a set of leaves to prove
	leavesToProve := map[uint64]struct{}{
		0: {},
		4: {},
		7: {},
	}
	// Create a set of proven leaves
	provenLeaves := make(map[uint64][]byte, len(leavesToProve))

	// Create a new Merkle tree
	tree := merkle.TreeBuilder().
		WithLeavesToProve(leavesToProve).
		Build()

	// Add some data to the tree
	b := make([]byte, tree.NodeSize())
	for i := range 8 {
		binary.LittleEndian.PutUint64(b, uint64(i))
		tree.Add(b)

		if _, ok := leavesToProve[uint64(i)]; ok {
			provenLeaves[uint64(i)] = make([]byte, len(b))
			copy(provenLeaves[uint64(i)], b)
		}
	}

	// Print the root hash
	root, proof := tree.RootAndProof()
	rootString := hex.EncodeToString(root)
	fmt.Println("root:", rootString)

	// Print the proof
	fmt.Println("proof:")
	for i, p := range proof {
		fmt.Printf("\t%d: %x\n", i, p)
	}

	valid, err := merkle.ValidateProof(root, provenLeaves, proof)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Valid:", valid)

	// Output:
	// root: 89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce
	// proof:
	// 	0: 0100000000000000000000000000000000000000000000000000000000000000
	// 	1: 0094579cfc7b716038d416a311465309bea202baa922b224a7b08f01599642fb
	// 	2: 0500000000000000000000000000000000000000000000000000000000000000
	// 	3: 0600000000000000000000000000000000000000000000000000000000000000
	// Valid: true
}

func TestValidateProof(t *testing.T) {
	t.Parallel()

	leaves := make(map[uint64][]byte)
	leaves[4], _ = hex.DecodeString("0400000000000000000000000000000000000000000000000000000000000000")

	root, _ := hex.DecodeString("89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce")
	proof := make([][]byte, 3)
	proof[0], _ = hex.DecodeString("0500000000000000000000000000000000000000000000000000000000000000")
	proof[1], _ = hex.DecodeString("fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088")
	proof[2], _ = hex.DecodeString("ba94ffe7edabf26ef12736f8eb5ce74d15bedb6af61444ae2906e926b1a95084")

	valid, err := merkle.ValidateProof(root, leaves, proof)
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("proof is not valid")
	}

	// check that the root and proof have not changed
	rootString := hex.EncodeToString(root)
	if rootString != "89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce" {
		t.Errorf("root has changed: %s", rootString)
	}

	if len(leaves) != 1 {
		t.Errorf("provenLeaves length has changed: %d", len(leaves))
	}
	provenLeafString := hex.EncodeToString(leaves[4])
	if provenLeafString != "0400000000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("provenLeaves[4] has changed: %s", provenLeafString)
	}

	expectedProof := []string{
		"0500000000000000000000000000000000000000000000000000000000000000",
		"fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088",
		"ba94ffe7edabf26ef12736f8eb5ce74d15bedb6af61444ae2906e926b1a95084",
	}
	if len(proof) != len(expectedProof) {
		t.Errorf("proof length has changed: %d", len(proof))
	}
	for i, p := range proof {
		if hex.EncodeToString(p) != expectedProof[i] {
			t.Errorf("proof[%d] has changed: %s", i, hex.EncodeToString(p))
		}
	}
}

func TestValidateMultiProof(t *testing.T) {
	t.Parallel()

	leaves := make(map[uint64][]byte)
	leaves[0], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	leaves[1], _ = hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	leaves[4], _ = hex.DecodeString("0400000000000000000000000000000000000000000000000000000000000000")

	root, _ := hex.DecodeString("89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce")
	proof := make([][]byte, 3)
	proof[0], _ = hex.DecodeString("0094579cfc7b716038d416a311465309bea202baa922b224a7b08f01599642fb")
	proof[1], _ = hex.DecodeString("0500000000000000000000000000000000000000000000000000000000000000")
	proof[2], _ = hex.DecodeString("fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088")

	valid, err := merkle.ValidateProof(root, leaves, proof)
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("proof is not valid")
	}
}

func TestValidateProofUnbalanced(t *testing.T) {
	t.Parallel()

	leaves := make(map[uint64][]byte)
	leaves[8], _ = hex.DecodeString("0800000000000000000000000000000000000000000000000000000000000000")

	root, _ := hex.DecodeString("59f32a43534fe4c4c0966421aef624267cdf65bd11f74998c60f27c7caccb12d")
	proof := make([][]byte, 4)
	proof[0], _ = hex.DecodeString("0900000000000000000000000000000000000000000000000000000000000000")
	proof[1], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	proof[2], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	proof[3], _ = hex.DecodeString("89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce")

	valid, err := merkle.ValidateProof(root, leaves, proof)
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("proof is not valid")
	}
}

func TestValidateMultiProofUnbalanced(t *testing.T) {
	t.Parallel()

	leaves := make(map[uint64][]byte)
	leaves[0], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	leaves[4], _ = hex.DecodeString("0400000000000000000000000000000000000000000000000000000000000000")
	leaves[8], _ = hex.DecodeString("0800000000000000000000000000000000000000000000000000000000000000")

	root, _ := hex.DecodeString("59f32a43534fe4c4c0966421aef624267cdf65bd11f74998c60f27c7caccb12d")
	proof := make([][]byte, 7)
	proof[0], _ = hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	proof[1], _ = hex.DecodeString("0094579cfc7b716038d416a311465309bea202baa922b224a7b08f01599642fb")
	proof[2], _ = hex.DecodeString("0500000000000000000000000000000000000000000000000000000000000000")
	proof[3], _ = hex.DecodeString("fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088")
	proof[4], _ = hex.DecodeString("0900000000000000000000000000000000000000000000000000000000000000")
	proof[5], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	proof[6], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")

	valid, err := merkle.ValidateProof(root, leaves, proof)
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("proof is not valid")
	}
}

// TODO(mafa): add TestValidateProofSequentialWork
// TODO(mafa): add TestValidateMultiProofSequentialWork
// TODO(mafa): add TestValidateProofUnbalancedSequentialWork
// TODO(mafa): add TestValidateMultiProofUnbalancedSequentialWork

func TestValidateWithHasher(t *testing.T) {
	t.Parallel()

	leaves := make(map[uint64][]byte)
	leaves[4], _ = hex.DecodeString("04")

	root, _ := hex.DecodeString("0001020304050607")
	proof := make([][]byte, 3)
	proof[0], _ = hex.DecodeString("05")
	proof[1], _ = hex.DecodeString("0607")
	proof[2], _ = hex.DecodeString("00010203")

	valid, err := merkle.ValidateProof(root, leaves, proof, merkle.WithHasher(concatHasher{}))
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("proof is not valid")
	}
}

// TODO(mafa): add TestValidateWithLeafHasher

func TestValidateProofInvalid(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name string
		root string

		leaf      string
		leafIndex uint64
		proof     []string

		valid bool
		err   error
	}{
		{
			name:      "invalid root",
			root:      "0000000000000000000000000000000000000000000000000000000000000000",
			leaf:      "0400000000000000000000000000000000000000000000000000000000000000",
			leafIndex: 4,
			proof: []string{
				"0500000000000000000000000000000000000000000000000000000000000000",
				"fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088",
				"ba94ffe7edabf26ef12736f8eb5ce74d15bedb6af61444ae2906e926b1a95084",
			},
			err:   nil,
			valid: false,
		},
		{
			name:      "invalid proof",
			root:      "89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce",
			leaf:      "0400000000000000000000000000000000000000000000000000000000000000",
			leafIndex: 4,
			proof: []string{
				"0500000000000000000000000000000000000000000000000000000000000000",
				"fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088",
				"0000000000000000000000000000000000000000000000000000000000000000", // invalid node
			},
			err:   nil,
			valid: false,
		},
		{
			name:      "short proof",
			root:      "89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce",
			leaf:      "0400000000000000000000000000000000000000000000000000000000000000",
			leafIndex: 4,
			proof: []string{
				"0500000000000000000000000000000000000000000000000000000000000000",
				"fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088",
				// missing node
			},
			err:   merkle.ErrShortProof,
			valid: false,
		},
		{
			name:      "proof padding",
			root:      "89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce",
			leaf:      "0400000000000000000000000000000000000000000000000000000000000000",
			leafIndex: 4,
			proof: []string{
				"0500000000000000000000000000000000000000000000000000000000000000",
				"fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088",
				"ba94ffe7edabf26ef12736f8eb5ce74d15bedb6af61444ae2906e926b1a95084",
				"0000000000000000000000000000000000000000000000000000000000000000", // padding
			},
			err:   nil,
			valid: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provenLeaves := make(map[uint64][]byte)
			provenLeaves[tc.leafIndex], _ = hex.DecodeString(tc.leaf)

			root, _ := hex.DecodeString(tc.root)
			proof := make([][]byte, len(tc.proof))
			for i, p := range tc.proof {
				proof[i], _ = hex.DecodeString(p)
			}

			valid, err := merkle.ValidateProof(root, provenLeaves, proof)
			if !errors.Is(err, tc.err) {
				t.Errorf("expected error: %v, got: %v", tc.err, err)
			}
			if tc.valid != valid {
				t.Errorf("expected valid: %t, got: %t", tc.valid, valid)
			}
		})
	}
}

func TestValidateProofEmpty(t *testing.T) {
	t.Parallel()

	// Test with empty root and proof
	root := make([]byte, 32)
	proof := make([][]byte, 0)
	leaves := make(map[uint64][]byte)

	valid, err := merkle.ValidateProof(root, leaves, proof)
	if !errors.Is(err, merkle.ErrNoLeaves) {
		t.Errorf("expected error: %v, got: %v", merkle.ErrNoLeaves, err)
	}
	if valid {
		t.Error("expected proof to be invalid")
	}
}

// Benchmark results
//
// goos: linux
// goarch: arm64
// pkg: github.com/fasmat/merkle
// BenchmarkValidateProof-10                 977810              1216 ns/op            1721 B/op          9 allocs/op
// BenchmarkValidateMultiProof-10            601164              1798 ns/op            1933 B/op         17 allocs/op
// PASS

// TODO(mafa): check if number of allocations can be reduced when sequential work is not used

func BenchmarkValidateProof(b *testing.B) {
	leaves := make(map[uint64][]byte)
	leaves[4], _ = hex.DecodeString("0400000000000000000000000000000000000000000000000000000000000000")

	root, _ := hex.DecodeString("89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce")
	proof := make([][]byte, 3)
	proof[0], _ = hex.DecodeString("0500000000000000000000000000000000000000000000000000000000000000")
	proof[1], _ = hex.DecodeString("fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088")
	proof[2], _ = hex.DecodeString("ba94ffe7edabf26ef12736f8eb5ce74d15bedb6af61444ae2906e926b1a95084")

	for b.Loop() {
		merkle.ValidateProof(root, leaves, proof) //nolint:errcheck
	}
}

func BenchmarkValidateMultiProof(b *testing.B) {
	leaves := make(map[uint64][]byte)
	leaves[0], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	leaves[1], _ = hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	leaves[4], _ = hex.DecodeString("0400000000000000000000000000000000000000000000000000000000000000")

	root, _ := hex.DecodeString("89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce")
	proof := make([][]byte, 3)
	proof[0], _ = hex.DecodeString("0094579cfc7b716038d416a311465309bea202baa922b224a7b08f01599642fb")
	proof[1], _ = hex.DecodeString("0500000000000000000000000000000000000000000000000000000000000000")
	proof[2], _ = hex.DecodeString("fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088")

	for b.Loop() {
		merkle.ValidateProof(root, leaves, proof) //nolint:errcheck
	}
}

// TODO(mafa): add BenchmarkValidateProofSequentialWork
// TODO(mafa): add BenchmarkValidateMultiProofSequentialWork

func FuzzValidate(f *testing.F) {
	// This fuzz test is used to ensure that the ValidateProof function does not panic
	// even when given invalid input.

	// Add a few test cases to the fuzzing function
	f.Add([]byte{}, uint64(0), uint64(0))
	f.Add([]byte{0x00}, uint64(1), uint64(1000))
	f.Add([]byte{0x01}, uint64(1000), uint64(1))

	f.Fuzz(func(_ *testing.T, root []byte, seed1, seed2 uint64) {
		pcg := rand.NewPCG(seed1, seed2)
		rng := rand.New(pcg)

		// Generate a random number of leaves
		numLeaves := rng.IntN(1000)
		leaves := make(map[uint64][]byte, numLeaves)
		for range numLeaves {
			// Generate a random leaf
			leaf := make([]byte, 32)
			binary.BigEndian.PutUint64(leaf, rng.Uint64())
			binary.BigEndian.PutUint64(leaf[8:], rng.Uint64())
			binary.BigEndian.PutUint64(leaf[16:], rng.Uint64())
			binary.BigEndian.PutUint64(leaf[24:], rng.Uint64())
			leaves[rand.Uint64()] = leaf
		}

		// Generate a random proof
		proofLen := rng.IntN(1000)
		proof := make([][]byte, proofLen)
		for i := range proofLen {
			// Generate a random proof node
			proofNode := make([]byte, 32)
			binary.BigEndian.PutUint64(proofNode, rng.Uint64())
			binary.BigEndian.PutUint64(proofNode[8:], rng.Uint64())
			binary.BigEndian.PutUint64(proofNode[16:], rng.Uint64())
			binary.BigEndian.PutUint64(proofNode[24:], rng.Uint64())
			proof[i] = proofNode
		}

		merkle.ValidateProof(root, leaves, proof) //nolint:errcheck
	})
}

func FuzzBuildAndValidateProof(f *testing.F) {
	// This fuzz test is used to ensure that a proof generated by a merkle.Tree can be validated
	// with the ValidateProof function.

	// Add a few test cases to the fuzzing function
	f.Add(uint64(2), uint64(1))
	f.Add(uint64(1000), uint64(1000))
	f.Add(uint64(2000), uint64(440))

	f.Fuzz(func(t *testing.T, numLeaves, numLeavesToProve uint64) {
		if numLeaves == 0 || numLeavesToProve == 0 {
			t.Skip("numLeaves and numLeavesToProve must be greater than 0")
		}
		if numLeaves < numLeavesToProve {
			t.Skip("numLeaves must be greater than numLeavesToProve")
		}
		leavesToProve := make(map[uint64]struct{}, numLeavesToProve)

		idx := float64(numLeaves)/float64(numLeavesToProve) - 1
		for range int(numLeavesToProve) {
			leavesToProve[uint64(idx)] = struct{}{}
			idx += float64(numLeaves) / float64(numLeavesToProve)
		}
		leaves := make(map[uint64][]byte, numLeaves)

		tree := merkle.TreeBuilder().
			WithLeavesToProve(leavesToProve).
			Build()

		for i := range numLeaves {
			b := make([]byte, tree.NodeSize())
			binary.LittleEndian.PutUint64(b, i)
			tree.Add(b)

			if _, ok := leavesToProve[uint64(i)]; ok {
				leaves[uint64(i)] = make([]byte, len(b))
				copy(leaves[uint64(i)], b)
			}
		}

		root, proof := tree.RootAndProof()

		ok, err := merkle.ValidateProof(root, leaves, proof)
		if err != nil {
			t.Errorf("Error validating proof: %v", err)
		}
		if !ok {
			t.Errorf("Proof validation failed for root %x", root)
		}
	})
}

// TODO(mafa): add FuzzBuildAndValidateProofSequentialWork
