package merkle_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/fasmat/merkle"
)

//nolint:gocyclo // linter is overly sensitive here, this is a test
func TestFileLayerCache(t *testing.T) {
	t.Parallel()

	t.Run("Append", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		cache, err := merkle.NewFileLayerCache(dir)
		if err != nil {
			t.Fatalf("failed to create file layer cache: %v", err)
		}

		data := make([]byte, 32)
		copy(data, []byte("test data"))
		if err := cache.Append(0, data); err != nil {
			t.Fatalf("failed to append data to cache: %v", err)
		}
		read, err := cache.ReadAt(0, 0)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("failed to read data from cache: %v", err)
		}
		if !bytes.Equal(data, read) {
			t.Errorf("unexpected data read from cache:\ngot  %q,\nwant %q", read, data)
		}
		length, err := cache.Len(0)
		if err != nil {
			t.Fatalf("failed to get cache length: %v", err)
		}
		if length != 1 {
			t.Errorf("unexpected cache length: got %d, want %d", length, 1)
		}
	})

	t.Run("ReadAt", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		cache, err := merkle.NewFileLayerCache(dir)
		if err != nil {
			t.Fatalf("failed to create file layer cache: %v", err)
		}

		data := make([]byte, 32)
		for i := range 100 {
			binary.LittleEndian.PutUint32(data, uint32(i))
			if err := cache.Append(0, data); err != nil {
				t.Fatalf("failed to append data to cache: %v", err)
			}
		}

		for i := range 100 {
			read, err := cache.ReadAt(0, i)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("failed to read data from cache: %v", err)
			}
			binary.LittleEndian.PutUint32(data, uint32(i))
			if !bytes.Equal(data, read) {
				t.Errorf("unexpected data read from cache:\ngot  %q,\nwant %q", read, data)
			}
		}

		length, err := cache.Len(0)
		if err != nil {
			t.Fatalf("failed to get cache length: %v", err)
		}
		if length != 100 {
			t.Errorf("unexpected cache length: got %d, want %d", length, 100)
		}
	})

	t.Run("Append after ReadAt", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		cache, err := merkle.NewFileLayerCache(dir)
		if err != nil {
			t.Fatalf("failed to create file layer cache: %v", err)
		}

		data := make([]byte, 32)
		for i := range 100 {
			binary.LittleEndian.PutUint32(data, uint32(i))
			if err := cache.Append(0, data); err != nil {
				t.Fatalf("failed to append data to cache: %v", err)
			}
		}

		read, err := cache.ReadAt(0, 0)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("failed to read data from cache: %v", err)
		}
		binary.LittleEndian.PutUint32(data, 0)
		if !bytes.Equal(data, read) {
			t.Errorf("unexpected data read from cache:\ngot  %q,\nwant %q", read, data)
		}

		newData := make([]byte, 32)
		copy(newData, []byte("new test data"))
		if err := cache.Append(0, newData); err != nil {
			t.Fatalf("failed to append new data to cache: %v", err)
		}

		readNew, err := cache.ReadAt(0, 100)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("failed to read new data from cache: %v", err)
		}
		if !bytes.Equal(newData, readNew) {
			t.Errorf("unexpected new data read from cache:\ngot  %q,\nwant %q", readNew, newData)
		}
	})
}
