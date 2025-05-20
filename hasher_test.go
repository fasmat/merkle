package merkle_test

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/fasmat/merkle"
)

func ExampleBuilder_WithLeafHasher() {
	// Create a merkle tree that uses a leaf hasher.
	tree := merkle.TreeBuilder().
		WithLeafHasher(merkle.SequentialWorkHasher()).
		Build()

	// Add some data to the tree
	b := make([]byte, tree.NodeSize())
	for i := range 8 {
		binary.LittleEndian.PutUint64(b, uint64(i))
		tree.Add(b)
	}

	// TODO(mafa): add validate

	// Print the root hash
	rootString := hex.EncodeToString(tree.Root())
	fmt.Println(rootString) // Output: 02ce397ec513f034dd6ec5dce3cdb8bfcf10f400a9979cb03abf52d3b5f6c88b
}
