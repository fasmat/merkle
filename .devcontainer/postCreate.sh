#!/bin/bash

# Install gofumpt
go install mvdan.cc/gofumpt@v0.7.0

# Copy the golangci-lint binary to a new name (workaround until vscode-go supports v2)
cp /go/bin/golangci-lint /go/bin/golangci-lint-v2
