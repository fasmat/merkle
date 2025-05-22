# merkle Changelog

## v0.3.0 (unreleased)

* ci: measure cyclomatic complexity and keep it below 15
* feat: add option to use proof of sequential work when building and verifying a the tree, for details see readme and godoc

## v0.2.1 (2025-05-20)

* chore: use slices instead of objects to track parked nodes
* ci: add release workflow to automatically create a release on tag
* docs: improve godoc comments and add more examples
* docs: add CHANGELOG.md to the repository
* fix: `TreeBuilder().WithMinHeight()` now works correctly, before it was off by one

## v0.2.0 (2025-05-18)

* chore: added more tests to increase coverage
* chore: added benchmarks to track performance
* chore: optimized the code for better performance
* ci: code coverage is now tracked by `codecov`
* docs: updated README.md with more information and animation of the merkle tree
* feat: added a new functionality to create and verify merkle proofs

## v0.1.0 (2025-05-07)

* Initial Release
