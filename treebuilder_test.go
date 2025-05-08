package merkle

import (
	"slices"
	"testing"
)

func TestWithLeavesNotSet(t *testing.T) {
	t.Parallel()

	tree := TreeBuilder().Build()
	if tree.leavesToProve != nil {
		t.Errorf("Expected leaves to prove to be empty, got %v", tree.leavesToProve)
	}
}

func TestWithLeafToProveUnion(t *testing.T) {
	t.Parallel()

	tree := TreeBuilder().
		WithLeafToProve(0).
		WithLeafToProve(1).
		WithLeafToProve(0).
		WithLeafToProve(2).
		Build()
	if !slices.Equal([]uint64{0, 1, 2}, tree.leavesToProve) {
		t.Errorf("Expected leaves to prove to be [0, 1, 2], got %v", tree.leavesToProve)
	}
}

func TestWithLeavesToProveUnion(t *testing.T) {
	t.Parallel()

	leaves1 := map[uint64]struct{}{
		0: {},
		1: {},
	}
	leaves2 := map[uint64]struct{}{
		1: {},
		2: {},
	}
	tree := TreeBuilder().
		WithLeavesToProve(leaves1).
		WithLeavesToProve(leaves2).
		Build()
	if !slices.Equal([]uint64{0, 1, 2}, tree.leavesToProve) {
		t.Errorf("Expected leaves to prove to be [0, 1, 2], got %v", tree.leavesToProve)
	}
}
