# merkle

[![Build Status](https://img.shields.io/github/actions/workflow/status/fasmat/merkle/ci.yml)](https://github.com/fasmat/merkle/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/fasmat/merkle/graph/badge.svg?token=2WFR1O5B42)](https://codecov.io/gh/fasmat/merkle)
[![Go Report Card](https://goreportcard.com/badge/github.com/fasmat/merkle)](https://goreportcard.com/report/github.com/fasmat/merkle)
[![Go Reference](https://pkg.go.dev/badge/github.com/fasmat/merkle?status.svg)](https://pkg.go.dev/github.com/fasmat/merkle?tab=doc)
[![License](https://img.shields.io/github/license/fasmat/merkle)](./LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/fasmat/merkle)](https://github.com/fasmat/merkle/releases/latest)

**merkle** is a simple Go library for creating and verifying Merkle trees. It is designed to be easy to use, while
remaining efficient and secure.

## Usage

For usage examples and API documentation, see the [GoDoc](https://pkg.go.dev/github.com/fasmat/merkle?tab=doc).

## How It Works

### Tree Construction

The Merkle tree is constructed sequentially and stored in memory. The [`Tree.Add`](https://pkg.go.dev/github.com/fasmat/merkle#Tree.Add) method calculates the root incrementally and retains only the nodes that do not yet have a sibling. As a result, at most `O(log₂ n)` memory is used, where `n` is the number of leaves added to the tree.

The tree is built bottom-up: each node is derived from its children. The [`Tree.Root`](https://pkg.go.dev/github.com/fasmat/merkle#Tree.Root) method returns the root hash of the tree, padding with zero values to the right if a node lacks a sibling.

_TODO (mafa): Add a diagram illustrating tree construction._

### Proof Generation and Verification

You can generate a Merkle proof for one or more leaves using [`Builder.WithLeafToProve`](https://pkg.go.dev/github.com/fasmat/merkle#Builder.WithLeafToProve) or [`Builder.WithLeavesToProve`](https://pkg.go.dev/github.com/fasmat/merkle#Builder.WithLeavesToProve). The resulting proof is a list of hashes required to verify the inclusion of the specified leaves in the tree.

The proof is constructed by collecting the sibling hashes of nodes that cannot be derived solely from the proven leaves. These hashes are returned in the order necessary to verify the inclusion path back to the root, as produced by [`Tree.RootAndProof`](https://pkg.go.dev/github.com/fasmat/merkle#Tree.RootAndProof).

The proof can be verified using the [`ValidateProof`](https://pkg.go.dev/github.com/fasmat/merkle#ValidateProof) function.

_TODO (mafa): Add a diagram illustrating proof generation and verification._
