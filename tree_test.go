package merkle_test

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/fasmat/merkle"
)

func ExampleNewTree() {
	// Create a new Merkle tree
	tree := merkle.NewTree()

	// Add some data to the tree
	b := make([]byte, tree.NodeSize())
	for i := range 8 {
		binary.LittleEndian.PutUint64(b, uint64(i))
		tree.Add(b)
	}

	// Print the root hash
	rootString := hex.EncodeToString(tree.Root())
	fmt.Println(rootString) // Output: 89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce
}

func TestExampleTree_Detailed(t *testing.T) {
	t.Parallel()

	hasher := merkle.Sha256()
	lChild := make([]byte, hasher.Size())
	binary.LittleEndian.PutUint64(lChild, 0)
	rChild := make([]byte, hasher.Size())
	binary.LittleEndian.PutUint64(rChild, 1)

	// Hash the two child hashes
	root1 := hasher.Hash(nil, lChild, rChild)
	rootString := hex.EncodeToString(root1)
	if rootString != "cb592844121d926f1ca3ad4e1d6fb9d8e260ed6e3216361f7732e975a0e8bbf6" {
		t.Errorf(
			"Expected hash to be cb592844121d926f1ca3ad4e1d6fb9d8e260ed6e3216361f7732e975a0e8bbf6, got %s",
			hex.EncodeToString(root1),
		)
	}

	// Hash the next two child hashes
	binary.LittleEndian.PutUint64(lChild, 2)
	binary.LittleEndian.PutUint64(rChild, 3)
	root2 := hasher.Hash(nil, lChild, rChild)
	rootString = hex.EncodeToString(root2)
	if rootString != "0094579cfc7b716038d416a311465309bea202baa922b224a7b08f01599642fb" {
		t.Errorf(
			"Expected hash to be 0094579cfc7b716038d416a311465309bea202baa922b224a7b08f01599642fb, got %s",
			hex.EncodeToString(root2),
		)
	}

	// Hash child 5 and 6
	binary.LittleEndian.PutUint64(lChild, 4)
	binary.LittleEndian.PutUint64(rChild, 5)
	root3 := hasher.Hash(nil, lChild, rChild)
	rootString = hex.EncodeToString(root3)
	if rootString != "bd50456d5ad175ae99a1612a53ca229124b65d3eaabd9ff9c7ab979a385cf6b3" {
		t.Errorf(
			"Expected hash to be bd50456d5ad175ae99a1612a53ca229124b65d3eaabd9ff9c7ab979a385cf6b3, got %s",
			hex.EncodeToString(root3),
		)
	}

	// Hash child 7 and 8
	binary.LittleEndian.PutUint64(lChild, 6)
	binary.LittleEndian.PutUint64(rChild, 7)
	root4 := hasher.Hash(nil, lChild, rChild)
	rootString = hex.EncodeToString(root4)
	if rootString != "fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088" {
		t.Errorf(
			"Expected hash to be fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088, got %s",
			hex.EncodeToString(root4),
		)
	}

	// Hash the two roots together
	firstRoot := hasher.Hash(nil, root1, root2)
	rootString = hex.EncodeToString(firstRoot)
	if rootString != "ba94ffe7edabf26ef12736f8eb5ce74d15bedb6af61444ae2906e926b1a95084" {
		t.Errorf(
			"Expected hash to be ba94ffe7edabf26ef12736f8eb5ce74d15bedb6af61444ae2906e926b1a95084, got %s",
			hex.EncodeToString(firstRoot),
		)
	}

	// Hash the two roots together
	secondRoot := hasher.Hash(nil, root3, root4)
	rootString = hex.EncodeToString(secondRoot)
	if rootString != "633b26ee8a5d96d49a4861e9a5720492f0db5b6af305c0b5cfcc6a7ec9b676d4" {
		t.Errorf(
			"Expected hash to be 633b26ee8a5d96d49a4861e9a5720492f0db5b6af305c0b5cfcc6a7ec9b676d4, got %s",
			hex.EncodeToString(secondRoot),
		)
	}

	// Hash final roots together
	finalRoot := hasher.Hash(nil, firstRoot, secondRoot)
	rootString = hex.EncodeToString(finalRoot)
	if rootString != "89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce" {
		t.Errorf(
			"Expected hash to be 89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce, got %s",
			hex.EncodeToString(finalRoot),
		)
	}
}

func TestTreeUnbalanced(t *testing.T) {
	t.Parallel()

	tt := []struct {
		numElements  int
		expectedRoot string
	}{
		{9, "cb71c80ee780788eedb819ec125a41e0cde57bd0955cdd3157ca363193ab5ff1"},
		{10, "59f32a43534fe4c4c0966421aef624267cdf65bd11f74998c60f27c7caccb12d"},
		{15, "b9746fb884ed07041c5cbb3bb5526e1383928e832a8385e08db995966889b5a8"},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("numElements=%d", tc.numElements), func(t *testing.T) {
			t.Parallel()

			tree := merkle.NewTree()

			b := make([]byte, tree.NodeSize())
			for i := range tc.numElements {
				binary.LittleEndian.PutUint64(b, uint64(i))
				tree.Add(b)
			}

			rootString := hex.EncodeToString(tree.Root())
			if rootString != tc.expectedRoot {
				t.Errorf("Expected hash to be %s, got %s", tc.expectedRoot, rootString)
			}
		})
	}
}

func TestTreeAddAfterRootUpdatesRoot(t *testing.T) {
	t.Parallel()

	tree := merkle.NewTree()
	buf := make([]byte, tree.NodeSize())
	for i := range 8 {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		tree.Add(buf)
	}

	rootString := hex.EncodeToString(tree.Root())
	if rootString != "89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce" {
		t.Errorf(
			"Expected hash to be 89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce, got %s",
			rootString,
		)
	}

	binary.LittleEndian.PutUint64(buf, 8)
	tree.Add(buf)

	rootString = hex.EncodeToString(tree.Root())
	if rootString != "cb71c80ee780788eedb819ec125a41e0cde57bd0955cdd3157ca363193ab5ff1" {
		t.Errorf(
			"Expected hash to be cb71c80ee780788eedb819ec125a41e0cde57bd0955cdd3157ca363193ab5ff1, got %s",
			rootString,
		)
	}
}

func TestTreeMinHeightEqual(t *testing.T) {
	t.Parallel()

	tree := merkle.TreeBuilder().
		WithHasher(concatHasher{}).
		WithMinHeight(3).
		Build()

	for i := range 8 {
		tree.Add([]byte{byte(i)})
	}

	rootString := hex.EncodeToString(tree.Root())
	if rootString != "0001020304050607" {
		t.Errorf("Expected hash to be 0001020304050607, got %s", rootString)
	}
}

func TestTreeMinHeightLess(t *testing.T) {
	t.Parallel()

	tree := merkle.TreeBuilder().
		WithHasher(concatHasher{}).
		WithMinHeight(2).
		Build()

	for i := range 8 {
		tree.Add([]byte{byte(i)})
	}

	rootString := hex.EncodeToString(tree.Root())
	if rootString != "0001020304050607" {
		t.Errorf("Expected hash to be 0001020304050607, got %s", rootString)
	}
}

func TestTreeMinHeightGreater(t *testing.T) {
	t.Parallel()

	tt := []struct {
		minHeight    uint64
		expectedRoot string
	}{
		{4, "000102030405060700"},   // need to add one padding node to root
		{5, "00010203040506070000"}, // need to add two padding nodes to root
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("minHeight=%d", tc.minHeight), func(t *testing.T) {
			t.Parallel()

			tree := merkle.TreeBuilder().
				WithHasher(concatHasher{}).
				WithMinHeight(tc.minHeight).
				Build()

			for i := range 8 {
				tree.Add([]byte{byte(i)})
			}

			rootString := hex.EncodeToString(tree.Root())
			if rootString != tc.expectedRoot {
				t.Errorf("Expected hash to be %s, got %s", tc.expectedRoot, rootString)
			}
		})
	}
}

type concatHasher struct{}

func (concatHasher) Size() int {
	return 1
}

func (concatHasher) Hash(_, lChild, rChild []byte) []byte {
	buf := make([]byte, 0, len(lChild)+len(rChild))
	buf = append(buf, lChild...)
	buf = append(buf, rChild...)
	return buf
}

func TestTreeProof(t *testing.T) {
	t.Parallel()

	tree := merkle.TreeBuilder().
		WithLeafToProve(4).
		Build()
	buf := make([]byte, tree.NodeSize())
	for i := range 8 {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		tree.Add(buf)
	}

	root, proof := tree.RootAndProof()
	rootString := hex.EncodeToString(root)
	if rootString != "89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce" {
		t.Errorf(
			"Expected hash to be 89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce, got %s",
			rootString,
		)
	}

	expectedProof := []string{
		"0500000000000000000000000000000000000000000000000000000000000000",
		"fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088",
		"ba94ffe7edabf26ef12736f8eb5ce74d15bedb6af61444ae2906e926b1a95084",
	}
	if len(proof) != len(expectedProof) {
		t.Fatalf("Expected proof to be of length %d, got %d", len(expectedProof), len(proof))
	}
	for i, p := range proof {
		pString := hex.EncodeToString(p)
		if pString != expectedProof[i] {
			t.Errorf("Expected proof[%d] to be %s, got %s", i, expectedProof[i], pString)
		}
	}
}

func TestTreeMultiProof(t *testing.T) {
	t.Parallel()

	tree := merkle.TreeBuilder().
		WithLeafToProve(0).
		WithLeafToProve(1).
		WithLeafToProve(4).
		Build()
	buf := make([]byte, tree.NodeSize())
	for i := range 8 {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		tree.Add(buf)
	}

	root, proof := tree.RootAndProof()
	rootString := hex.EncodeToString(root)
	if rootString != "89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce" {
		t.Errorf(
			"Expected hash to be 89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce, got %s",
			rootString,
		)
	}

	expectedProof := []string{
		"0094579cfc7b716038d416a311465309bea202baa922b224a7b08f01599642fb",
		"0500000000000000000000000000000000000000000000000000000000000000",
		"fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088",
	}
	if len(proof) != len(expectedProof) {
		t.Fatalf("Expected proof to be of length %d, got %d", len(expectedProof), len(proof))
	}
	for i, p := range proof {
		pString := hex.EncodeToString(p)
		if pString != expectedProof[i] {
			t.Errorf("Expected proof[%d] to be %s, got %s", i, expectedProof[i], pString)
		}
	}
}

func TestTreeProofUnbalanced(t *testing.T) {
	t.Parallel()

	tree := merkle.TreeBuilder().
		WithLeafToProve(8).
		Build()

	b := make([]byte, tree.NodeSize())
	for i := range 10 {
		binary.LittleEndian.PutUint64(b, uint64(i))
		tree.Add(b)
	}

	root, proof := tree.RootAndProof()
	rootString := hex.EncodeToString(root)
	if rootString != "59f32a43534fe4c4c0966421aef624267cdf65bd11f74998c60f27c7caccb12d" {
		t.Errorf(
			"Expected hash to be 59f32a43534fe4c4c0966421aef624267cdf65bd11f74998c60f27c7caccb12d, got %s",
			rootString,
		)
	}

	expectedProof := []string{
		"0900000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"89a0f1577268cc19b0a39c7a69f804fd140640c699585eb635ebb03c06154cce",
	}
	if len(proof) != len(expectedProof) {
		t.Fatalf("Expected proof to be of length %d, got %d", len(expectedProof), len(proof))
	}
	for i, p := range proof {
		pString := hex.EncodeToString(p)
		if pString != expectedProof[i] {
			t.Errorf("Expected proof[%d] to be %s, got %s", i, expectedProof[i], pString)
		}
	}
}

func TestTreeMultiProofUnbalanced(t *testing.T) {
	t.Parallel()

	tree := merkle.TreeBuilder().
		WithLeafToProve(0).
		WithLeafToProve(4).
		WithLeafToProve(8).
		Build()
	buf := make([]byte, tree.NodeSize())
	for i := range 10 {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		tree.Add(buf)
	}

	root, proof := tree.RootAndProof()
	rootString := hex.EncodeToString(root)
	if rootString != "59f32a43534fe4c4c0966421aef624267cdf65bd11f74998c60f27c7caccb12d" {
		t.Errorf(
			"Expected hash to be 59f32a43534fe4c4c0966421aef624267cdf65bd11f74998c60f27c7caccb12d, got %s",
			rootString,
		)
	}

	expectedProof := []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"0094579cfc7b716038d416a311465309bea202baa922b224a7b08f01599642fb",
		"0500000000000000000000000000000000000000000000000000000000000000",
		"fa670379e5c2212ed93ff09769622f81f98a91e1ec8fb114d607dd25220b9088",
		"0900000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000",
	}
	if len(proof) != len(expectedProof) {
		t.Fatalf("Expected proof to be of length %d, got %d", len(expectedProof), len(proof))
	}
	for i, p := range proof {
		pString := hex.EncodeToString(p)
		if pString != expectedProof[i] {
			t.Errorf("Expected proof[%d] to be %s, got %s", i, expectedProof[i], pString)
		}
	}
}

// Benchmark results
//
// goos: linux
// goarch: arm64
// pkg: github.com/fasmat/merkle
// BenchmarkTreeAdd-10                        11709153           102.7 ns/op            32 B/op          1 allocs/op
// BenchmarkTreeAddWithProof-10               11546602           102.8 ns/op            32 B/op          1 allocs/op
// BenchmarkTreeRootBalanced-10               55411255            21.38 ns/op            0 B/op          0 allocs/op
// BenchmarkTreeRootUnBalancedSmall-10         1253310           957.2 ns/op            32 B/op          1 allocs/op
// BenchmarkTreeRootUnBalancedBig-10           1000000          1046 ns/op              32 B/op          1 allocs/op
// BenchmarkTreeProofBalanced-10               4586818           260.2 ns/op           640 B/op         12 allocs/op
// BenchmarkTreeProofUnBalancedSmall-10        1000000          1185 ns/op             672 B/op         13 allocs/op
// BenchmarkTreeProofUnBalancedBig-10           837196          1307 ns/op             704 B/op         14 allocs/op
// PASS

func BenchmarkTreeAdd(b *testing.B) {
	tree := merkle.NewTree()
	buf := make([]byte, tree.NodeSize())
	for i := 0; b.Loop(); i++ {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		tree.Add(buf)
	}
}

func BenchmarkTreeAddWithProof(b *testing.B) {
	tree := merkle.TreeBuilder().
		WithLeafToProve(4).
		Build()
	buf := make([]byte, tree.NodeSize())
	for i := 0; b.Loop(); i++ {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		tree.Add(buf)
	}
}

func BenchmarkTreeRootBalanced(b *testing.B) {
	tree := merkle.NewTree()
	buf := make([]byte, tree.NodeSize())

	// Generate a balanced tree, in this case tree.Root() will only return the (already calculated) root
	for i := range 2048 {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		tree.Add(buf)
	}

	for i := 0; b.Loop(); i++ {
		tree.Root()
	}
}

func BenchmarkTreeRootUnBalancedSmall(b *testing.B) {
	tree := merkle.NewTree()
	buf := make([]byte, tree.NodeSize())

	// Generate an tree that has 1 fewer than a power of 2 leaves, in this case tree.Root() will have to calculate the
	// root by walking the tree up to the root.
	for i := range 2047 {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		tree.Add(buf)
	}

	for i := 0; b.Loop(); i++ {
		tree.Root()
	}
}

func BenchmarkTreeRootUnBalancedBig(b *testing.B) {
	tree := merkle.NewTree()
	buf := make([]byte, tree.NodeSize())

	// Generate an tree that has 1 more than a power of 2 leaves, in this case tree.Root() will have to calculate the
	// root by walking the tree up to the root and padding on the way.
	for i := range 2049 {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		tree.Add(buf)
	}

	for i := 0; b.Loop(); i++ {
		tree.Root()
	}
}

func BenchmarkTreeProofBalanced(b *testing.B) {
	tree := merkle.TreeBuilder().
		WithLeafToProve(1000).
		Build()
	buf := make([]byte, tree.NodeSize())
	for i := range 2048 {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		tree.Add(buf)
	}

	for i := 0; b.Loop(); i++ {
		tree.RootAndProof()
	}
}

func BenchmarkTreeProofUnBalancedSmall(b *testing.B) {
	tree := merkle.TreeBuilder().
		WithLeafToProve(1001).
		Build()
	buf := make([]byte, tree.NodeSize())
	for i := range 2047 {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		tree.Add(buf)
	}

	for i := 0; b.Loop(); i++ {
		tree.RootAndProof()
	}
}

func BenchmarkTreeProofUnBalancedBig(b *testing.B) {
	tree := merkle.TreeBuilder().
		WithLeafToProve(1000).
		Build()
	buf := make([]byte, tree.NodeSize())
	for i := range 2049 {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		tree.Add(buf)
	}

	for i := 0; b.Loop(); i++ {
		tree.RootAndProof()
	}
}
