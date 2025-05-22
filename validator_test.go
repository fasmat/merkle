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

func ExampleWithLeafHasher() {
	// Create a set of leaves to prove
	leavesToProve := map[uint64]struct{}{
		1: {},
		3: {},
		6: {},
	}
	// Create a set of proven leaves
	provenLeaves := make(map[uint64][]byte, len(leavesToProve))

	// Create a merkle tree that uses a leaf hasher.
	tree := merkle.TreeBuilder().
		WithLeavesToProve(leavesToProve).
		WithLeafHasher(merkle.SequentialWorkHasher()).
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

	valid, err := merkle.ValidateProof(root, provenLeaves, proof, merkle.WithLeafHasher(merkle.SequentialWorkHasher()))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Valid:", valid)

	// Output:
	// root: 02ce397ec513f034dd6ec5dce3cdb8bfcf10f400a9979cb03abf52d3b5f6c88b
	// proof:
	// 	0: 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
	// 	1: 838d183323751f3512ef22eee7ee284eda4e8d736ca70387ce68ee44ccbb0483
	// 	2: 2b4b14ec31fcd73cb55c8966bb8591ec57e617cfefd60df0f89d51b8bfd60df1
	// 	3: 628cd22dd9f320d3c32f9c4e830f00844e393a965d3c134147f73cb5f529b586
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

func TestValidateProofSequentialWork(t *testing.T) {
	t.Parallel()

	leaves := make(map[uint64][]byte)
	leaves[4], _ = hex.DecodeString("0400000000000000000000000000000000000000000000000000000000000000")

	root, _ := hex.DecodeString("02ce397ec513f034dd6ec5dce3cdb8bfcf10f400a9979cb03abf52d3b5f6c88b")
	proof := make([][]byte, 3)
	proof[0], _ = hex.DecodeString("03085fced9119406c955dc302885a509bf81972ead5fb8b1d87dd3308f9830a2")
	proof[1], _ = hex.DecodeString("64276da1ef80b4d466e654c5808c4ea3f2c57dda04499e0f495ac4593c746993")
	proof[2], _ = hex.DecodeString("c3831849e0ae67538cb54a4de0729118685c41822f714f7c466ee641380d01db")

	valid, err := merkle.ValidateProof(root, leaves, proof, merkle.WithLeafHasher(merkle.SequentialWorkHasher()))
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("proof is not valid")
	}

	// check that the root and proof have not changed
	rootString := hex.EncodeToString(root)
	if rootString != "02ce397ec513f034dd6ec5dce3cdb8bfcf10f400a9979cb03abf52d3b5f6c88b" {
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
		"03085fced9119406c955dc302885a509bf81972ead5fb8b1d87dd3308f9830a2",
		"64276da1ef80b4d466e654c5808c4ea3f2c57dda04499e0f495ac4593c746993",
		"c3831849e0ae67538cb54a4de0729118685c41822f714f7c466ee641380d01db",
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

func TestValidateMultiProofSequentialWork(t *testing.T) {
	t.Parallel()

	leaves := make(map[uint64][]byte)
	leaves[0], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	leaves[1], _ = hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	leaves[4], _ = hex.DecodeString("0400000000000000000000000000000000000000000000000000000000000000")

	root, _ := hex.DecodeString("02ce397ec513f034dd6ec5dce3cdb8bfcf10f400a9979cb03abf52d3b5f6c88b")
	proof := make([][]byte, 3)
	proof[0], _ = hex.DecodeString("9877cb740c0c4cd5a9a18df2ee05fae87951c73b7bd97cdcde297263783375da")
	proof[1], _ = hex.DecodeString("03085fced9119406c955dc302885a509bf81972ead5fb8b1d87dd3308f9830a2")
	proof[2], _ = hex.DecodeString("64276da1ef80b4d466e654c5808c4ea3f2c57dda04499e0f495ac4593c746993")

	valid, err := merkle.ValidateProof(root, leaves, proof, merkle.WithLeafHasher(merkle.SequentialWorkHasher()))
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("proof is not valid")
	}
}

func TestValidateProofUnbalancedSequentialWork(t *testing.T) {
	t.Parallel()

	leaves := make(map[uint64][]byte)
	leaves[8], _ = hex.DecodeString("0800000000000000000000000000000000000000000000000000000000000000")

	root, _ := hex.DecodeString("b52feaee4c84a2762112496115d927eae01122d61b0474fc74b288f2139f7b69")
	proof := make([][]byte, 4)
	proof[0], _ = hex.DecodeString("227fe68b5e59358c69e459b06fba730d6e66ca5ba895179dc9dd710ef25006cd")
	proof[1], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	proof[2], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	proof[3], _ = hex.DecodeString("02ce397ec513f034dd6ec5dce3cdb8bfcf10f400a9979cb03abf52d3b5f6c88b")

	valid, err := merkle.ValidateProof(root, leaves, proof, merkle.WithLeafHasher(merkle.SequentialWorkHasher()))
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("proof is not valid")
	}
}

func TestValidateMultiProofUnbalancedSequentialWork(t *testing.T) {
	t.Parallel()

	leaves := make(map[uint64][]byte)
	leaves[0], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	leaves[4], _ = hex.DecodeString("0400000000000000000000000000000000000000000000000000000000000000")
	leaves[8], _ = hex.DecodeString("0800000000000000000000000000000000000000000000000000000000000000")

	root, _ := hex.DecodeString("b52feaee4c84a2762112496115d927eae01122d61b0474fc74b288f2139f7b69")
	proof := make([][]byte, 7)
	proof[0], _ = hex.DecodeString("8877377eae7d7a824d658c6035955535504abb5a517183f28b012495d73e1666")
	proof[1], _ = hex.DecodeString("9877cb740c0c4cd5a9a18df2ee05fae87951c73b7bd97cdcde297263783375da")
	proof[2], _ = hex.DecodeString("03085fced9119406c955dc302885a509bf81972ead5fb8b1d87dd3308f9830a2")
	proof[3], _ = hex.DecodeString("64276da1ef80b4d466e654c5808c4ea3f2c57dda04499e0f495ac4593c746993")
	proof[4], _ = hex.DecodeString("227fe68b5e59358c69e459b06fba730d6e66ca5ba895179dc9dd710ef25006cd")
	proof[5], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	proof[6], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")

	valid, err := merkle.ValidateProof(root, leaves, proof, merkle.WithLeafHasher(merkle.SequentialWorkHasher()))
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("proof is not valid")
	}
}

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
// BenchmarkValidateProof-10                             773589          1319 ns/op        1869 B/op     12 allocs/op
// BenchmarkValidateMultiProof-10                        657993          1736 ns/op        1948 B/op     15 allocs/op
// BenchmarkValidateProofSequentialWork-10               546477          2086 ns/op        3505 B/op     16 allocs/op
// BenchmarkValidateMultiProofSequentialWork-10          392596          2808 ns/op        3582 B/op     19 allocs/op
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

func BenchmarkValidateProofSequentialWork(b *testing.B) {
	leaves := make(map[uint64][]byte)
	leaves[4], _ = hex.DecodeString("0400000000000000000000000000000000000000000000000000000000000000")

	root, _ := hex.DecodeString("02ce397ec513f034dd6ec5dce3cdb8bfcf10f400a9979cb03abf52d3b5f6c88b")
	proof := make([][]byte, 3)
	proof[0], _ = hex.DecodeString("03085fced9119406c955dc302885a509bf81972ead5fb8b1d87dd3308f9830a2")
	proof[1], _ = hex.DecodeString("64276da1ef80b4d466e654c5808c4ea3f2c57dda04499e0f495ac4593c746993")
	proof[2], _ = hex.DecodeString("c3831849e0ae67538cb54a4de0729118685c41822f714f7c466ee641380d01db")

	for b.Loop() {
		//nolint:errcheck
		merkle.ValidateProof(root, leaves, proof, merkle.WithLeafHasher(merkle.SequentialWorkHasher()))
	}
}

func BenchmarkValidateMultiProofSequentialWork(b *testing.B) {
	leaves := make(map[uint64][]byte)
	leaves[0], _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	leaves[1], _ = hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	leaves[4], _ = hex.DecodeString("0400000000000000000000000000000000000000000000000000000000000000")

	root, _ := hex.DecodeString("02ce397ec513f034dd6ec5dce3cdb8bfcf10f400a9979cb03abf52d3b5f6c88b")
	proof := make([][]byte, 3)
	proof[0], _ = hex.DecodeString("9877cb740c0c4cd5a9a18df2ee05fae87951c73b7bd97cdcde297263783375da")
	proof[1], _ = hex.DecodeString("03085fced9119406c955dc302885a509bf81972ead5fb8b1d87dd3308f9830a2")
	proof[2], _ = hex.DecodeString("64276da1ef80b4d466e654c5808c4ea3f2c57dda04499e0f495ac4593c746993")

	for b.Loop() {
		//nolint:errcheck
		merkle.ValidateProof(root, leaves, proof, merkle.WithLeafHasher(merkle.SequentialWorkHasher()))
	}
}

func FuzzValidate(f *testing.F) {
	f.Skip()
	// This fuzz test is used to ensure that the ValidateProof function does not panic
	// even when given invalid input.

	// Add a few test cases to the fuzzing function
	f.Add([]byte{}, []byte{0x00})
	f.Add([]byte{0x00}, []byte{0x00, 0x00})
	f.Add([]byte{0x01}, []byte{0x00, 0x01})

	f.Fuzz(func(_ *testing.T, root, seed []byte) {
		var chaChaSeed [32]byte
		copy(chaChaSeed[:], seed)
		rngSrc := rand.NewChaCha8(chaChaSeed)
		rng := rand.New(rngSrc)

		// Generate a random number of leaves
		numLeaves := rng.IntN(1000)
		leaves := make(map[uint64][]byte, numLeaves)
		for range numLeaves {
			// Generate a random leaf
			leaf := make([]byte, 32)
			binary.BigEndian.PutUint64(leaf, rng.Uint64())
			leaves[rand.Uint64()] = leaf
		}

		// Generate a random proof
		proofLen := rng.IntN(1000)
		proof := make([][]byte, proofLen)
		for i := range proofLen {
			// Generate a random proof node
			proofNode := make([]byte, 32)
			binary.BigEndian.PutUint64(proofNode, rng.Uint64())
			proof[i] = proofNode
		}

		merkle.ValidateProof(root, leaves, proof) //nolint:errcheck
	})
}

func FuzzBuildAndValidateProof(f *testing.F) {
	// This fuzz test is used to ensure that a proof generated by a merkle.Tree can be validated
	// with the ValidateProof function.

	// Add a few test cases to the fuzzing function
	f.Add(uint64(2), uint64(1), []byte{0x00})
	f.Add(uint64(1000), uint64(1000), []byte{0x01})
	f.Add(uint64(17), uint64(7), []byte{0x02})

	f.Fuzz(func(t *testing.T, numLeaves, numLeavesToProve uint64, seed []byte) {
		if numLeaves == 0 || numLeavesToProve == 0 {
			t.Skip("numLeaves and numLeavesToProve must be greater than 0")
		}
		if numLeaves < numLeavesToProve {
			t.Skip("numLeaves must be greater than numLeavesToProve")
		}

		var chaChaSeed [32]byte
		copy(chaChaSeed[:], seed)
		rngSrc := rand.NewChaCha8(chaChaSeed)
		rng := rand.New(rngSrc)
		leavesToProve := make(map[uint64]struct{}, numLeavesToProve)

		leafIndices := make([]uint64, numLeaves)
		for i := range numLeaves {
			leafIndices[i] = i
		}
		rng.Shuffle(int(numLeaves), func(i, j int) {
			leafIndices[i], leafIndices[j] = leafIndices[j], leafIndices[i]
		})
		leafIndices = leafIndices[:numLeavesToProve]
		for _, i := range leafIndices {
			leavesToProve[i] = struct{}{}
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

func FuzzBuildAndValidateProofSequentialWork(f *testing.F) {
	// This fuzz test is used to ensure that a proof generated by a merkle.Tree can be validated
	// with the ValidateProof function when using the SequentialWorkHasher.

	// Add a few test cases to the fuzzing function
	f.Add(uint64(2), uint64(1), []byte{0x00})
	f.Add(uint64(1000), uint64(1000), []byte{0x01})
	f.Add(uint64(17), uint64(7), []byte{0x02})

	f.Fuzz(func(t *testing.T, numLeaves, numLeavesToProve uint64, seed []byte) {
		if numLeaves == 0 || numLeavesToProve == 0 {
			t.Skip("numLeaves and numLeavesToProve must be greater than 0")
		}
		if numLeaves < numLeavesToProve {
			t.Skip("numLeaves must be greater than numLeavesToProve")
		}

		var chaChaSeed [32]byte
		copy(chaChaSeed[:], seed)
		rngSrc := rand.NewChaCha8(chaChaSeed)
		rng := rand.New(rngSrc)
		leavesToProve := make(map[uint64]struct{}, numLeavesToProve)

		leafIndices := make([]uint64, numLeaves)
		for i := range numLeaves {
			leafIndices[i] = i
		}
		rng.Shuffle(int(numLeaves), func(i, j int) {
			leafIndices[i], leafIndices[j] = leafIndices[j], leafIndices[i]
		})
		leafIndices = leafIndices[:numLeavesToProve]
		for _, i := range leafIndices {
			leavesToProve[i] = struct{}{}
		}
		leaves := make(map[uint64][]byte, numLeaves)

		tree := merkle.TreeBuilder().
			WithLeafHasher(merkle.SequentialWorkHasher()).
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

		ok, err := merkle.ValidateProof(root, leaves, proof, merkle.WithLeafHasher(merkle.SequentialWorkHasher()))
		if err != nil {
			t.Errorf("Error validating proof: %v", err)
		}
		if !ok {
			t.Errorf("Proof validation failed for root %x", root)
		}
	})
}
