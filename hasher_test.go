package merkle_test

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

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

	// Print the root hash
	rootString := hex.EncodeToString(tree.Root())
	fmt.Println(rootString) // Output: 02ce397ec513f034dd6ec5dce3cdb8bfcf10f400a9979cb03abf52d3b5f6c88b
}

func TestExampleBuilder_WithLeafHasher_Detailed(t *testing.T) {
	t.Parallel()

	hasher := merkle.Sha256()
	leafHasher := merkle.SequentialWorkHasher()

	lChild := make([]byte, hasher.Size())
	binary.LittleEndian.PutUint64(lChild, 0)
	leaf1 := leafHasher.Hash(nil, lChild, nil)
	leafString := hex.EncodeToString(leaf1)
	if leafString != "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925" {
		t.Errorf(
			"Expected hash to be 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925, got %s",
			leafString,
		)
	}

	rChild := make([]byte, hasher.Size())
	binary.LittleEndian.PutUint64(rChild, 1)
	leaf2 := leafHasher.Hash(nil, rChild, [][]byte{leaf1})
	leafString = hex.EncodeToString(leaf2)
	if leafString != "8877377eae7d7a824d658c6035955535504abb5a517183f28b012495d73e1666" {
		t.Errorf(
			"Expected hash to be 8877377eae7d7a824d658c6035955535504abb5a517183f28b012495d73e1666, got %s",
			leafString,
		)
	}

	root1 := hasher.Hash(nil, leaf1, leaf2)
	rootString := hex.EncodeToString(root1)
	if rootString != "d7a47552b854f77485306d4156b283c7d488e52e21055cdd83108624250fc9fb" {
		t.Errorf(
			"Expected hash to be d7a47552b854f77485306d4156b283c7d488e52e21055cdd83108624250fc9fb, got %s",
			rootString,
		)
	}

	binary.LittleEndian.PutUint64(lChild, 2)
	leaf3 := leafHasher.Hash(nil, lChild, [][]byte{root1})
	leafString = hex.EncodeToString(leaf3)
	if leafString != "838d183323751f3512ef22eee7ee284eda4e8d736ca70387ce68ee44ccbb0483" {
		t.Errorf(
			"Expected hash to be 838d183323751f3512ef22eee7ee284eda4e8d736ca70387ce68ee44ccbb0483, got %s",
			leafString,
		)
	}

	binary.LittleEndian.PutUint64(rChild, 3)
	leaf4 := leafHasher.Hash(nil, rChild, [][]byte{leaf3, root1})
	leafString = hex.EncodeToString(leaf4)
	if leafString != "4a003b3a5bb0e3652702586fbbe294d049ceb6fece2c8dd666a26c75f8991da4" {
		t.Errorf(
			"Expected hash to be 4a003b3a5bb0e3652702586fbbe294d049ceb6fece2c8dd666a26c75f8991da4, got %s",
			leafString,
		)
	}

	root2 := hasher.Hash(nil, leaf3, leaf4)
	rootString = hex.EncodeToString(root2)
	if rootString != "9877cb740c0c4cd5a9a18df2ee05fae87951c73b7bd97cdcde297263783375da" {
		t.Errorf(
			"Expected hash to be 9877cb740c0c4cd5a9a18df2ee05fae87951c73b7bd97cdcde297263783375da, got %s",
			rootString,
		)
	}

	firstRoot := hasher.Hash(nil, root1, root2)
	rootString = hex.EncodeToString(firstRoot)
	if rootString != "c3831849e0ae67538cb54a4de0729118685c41822f714f7c466ee641380d01db" {
		t.Errorf(
			"Expected hash to be c3831849e0ae67538cb54a4de0729118685c41822f714f7c466ee641380d01db, got %s",
			rootString,
		)
	}

	binary.LittleEndian.PutUint64(lChild, 4)
	leaf5 := leafHasher.Hash(nil, lChild, [][]byte{firstRoot})
	leafString = hex.EncodeToString(leaf5)
	if leafString != "5426245b9e8a5a27ca1b60e796236cee96b4c676b813889eb50818228190fb91" {
		t.Errorf(
			"Expected hash to be 5426245b9e8a5a27ca1b60e796236cee96b4c676b813889eb50818228190fb91, got %s",
			leafString,
		)
	}

	binary.LittleEndian.PutUint64(rChild, 5)
	leaf6 := leafHasher.Hash(nil, rChild, [][]byte{leaf5, firstRoot})
	leafString = hex.EncodeToString(leaf6)
	if leafString != "03085fced9119406c955dc302885a509bf81972ead5fb8b1d87dd3308f9830a2" {
		t.Errorf(
			"Expected hash to be 03085fced9119406c955dc302885a509bf81972ead5fb8b1d87dd3308f9830a2, got %s",
			leafString,
		)
	}

	root3 := hasher.Hash(nil, leaf5, leaf6)
	rootString = hex.EncodeToString(root3)
	if rootString != "628cd22dd9f320d3c32f9c4e830f00844e393a965d3c134147f73cb5f529b586" {
		t.Errorf(
			"Expected hash to be 628cd22dd9f320d3c32f9c4e830f00844e393a965d3c134147f73cb5f529b586, got %s",
			rootString,
		)
	}

	binary.LittleEndian.PutUint64(lChild, 6)
	leaf7 := leafHasher.Hash(nil, lChild, [][]byte{root3, firstRoot})
	leafString = hex.EncodeToString(leaf7)
	if leafString != "eb67bc5d1922a525ed3239ead501fd84c346291062632c070acd379b1cf932d9" {
		t.Errorf(
			"Expected hash to be eb67bc5d1922a525ed3239ead501fd84c346291062632c070acd379b1cf932d9, got %s",
			leafString,
		)
	}

	binary.LittleEndian.PutUint64(rChild, 7)
	leaf8 := leafHasher.Hash(nil, rChild, [][]byte{leaf7, root3, firstRoot})
	leafString = hex.EncodeToString(leaf8)
	if leafString != "2b4b14ec31fcd73cb55c8966bb8591ec57e617cfefd60df0f89d51b8bfd60df1" {
		t.Errorf(
			"Expected hash to be 2b4b14ec31fcd73cb55c8966bb8591ec57e617cfefd60df0f89d51b8bfd60df1, got %s",
			leafString,
		)
	}

	root4 := hasher.Hash(nil, leaf7, leaf8)
	rootString = hex.EncodeToString(root4)
	if rootString != "64276da1ef80b4d466e654c5808c4ea3f2c57dda04499e0f495ac4593c746993" {
		t.Errorf(
			"Expected hash to be 64276da1ef80b4d466e654c5808c4ea3f2c57dda04499e0f495ac4593c746993, got %s",
			rootString,
		)
	}

	secondRoot := hasher.Hash(nil, root3, root4)
	rootString = hex.EncodeToString(secondRoot)
	if rootString != "724e74c03744b4be63060f2e3f1fe14e93a2b2fe542e3d67460ead1273f7e9ee" {
		t.Errorf(
			"Expected hash to be 724e74c03744b4be63060f2e3f1fe14e93a2b2fe542e3d67460ead1273f7e9ee, got %s",
			rootString,
		)
	}

	finalRoot := hasher.Hash(nil, firstRoot, secondRoot)
	rootString = hex.EncodeToString(finalRoot)
	if rootString != "02ce397ec513f034dd6ec5dce3cdb8bfcf10f400a9979cb03abf52d3b5f6c88b" {
		t.Errorf(
			"Expected hash to be 02ce397ec513f034dd6ec5dce3cdb8bfcf10f400a9979cb03abf52d3b5f6c88b, got %s",
			rootString,
		)
	}
}
