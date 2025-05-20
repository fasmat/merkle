package merkle_test

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/fasmat/merkle"
)

func ExampleBuilder_WithLeafHasher() {
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
