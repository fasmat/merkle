package merkle

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// LayerCache is an interface that defines methods for reading and writing leafs and nodes to a cache.
type LayerCache interface {
	// Append adds a leaf or node to the cache for the given layer.
	Append(layer uint, data []byte) error

	// ReadAt retrieves a leaf or node from the cache for the given layer at the specified index.
	ReadAt(layer uint, index int) ([]byte, error)

	// Len returns the number of leafs or nodes in the cache for the given layer.
	Len(layer uint) (int, error)
}

// noOpLayerCache is a no-operation implementation of LayerCache.
type noOpLayerCache struct{}

func (noOpLayerCache) Append(_ uint, _ []byte) error {
	return nil
}

func (noOpLayerCache) ReadAt(_ uint, _ int) ([]byte, error) {
	return nil, nil
}

func (noOpLayerCache) Len(_ uint) (int, error) {
	return 0, nil
}

type fileLayerCache struct {
	// path is the directory where layer files are stored
	path string

	// file handles for each layer
	files map[uint]*os.File
}

// NewFileLayerCache creates a new LayerCache that uses the file system for persistence.
// The path parameter specifies the directory where the cache files will be stored.
// It is expected that the directory exists and is writable.
// If the directory does not exist, an error will be returned.
// Every layer will be stored in a separate file named "layer_<layer>.bin" in the specified directory.
func NewFileLayerCache(path string) (LayerCache, error) {
	f, err := os.Stat(path)
	switch {
	case os.IsNotExist(err):
		return nil, fmt.Errorf("directory does not exist: %w", err)
	case err != nil:
		return nil, fmt.Errorf("error checking directory: %w", err)
	case !f.IsDir():
		return nil, fmt.Errorf("path is not a directory: %s", path)
	}

	// open all files that match the pattern "layer_<layer>.bin"
	dir, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("error reading directory: %w", err)
	}

	re := regexp.MustCompile(`^layer_(\d+)\.bin$`) // Compile the regex pattern for matching file names
	files := make(map[uint]*os.File)
	for _, entry := range dir {
		if entry.IsDir() {
			continue // Skip directories
		}
		// Check if the file name matches the expected pattern
		// "layer_<layer>.bin" where <layer> is a number
		matches := re.FindStringSubmatch(entry.Name())
		if matches == nil {
			continue // Skip files that do not match the pattern
		}
		layer, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("error parsing layer number from file name %s: %w", entry.Name(), err)
		}
		file, err := os.OpenFile(filepath.Join(path, entry.Name()), os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			return nil, fmt.Errorf("error opening file %s: %w", entry.Name(), err)
		}
		files[uint(layer)] = file
	}

	return &fileLayerCache{
		path: path,

		files: files,
	}, nil
}

func (f *fileLayerCache) openFile(layer uint) (*os.File, error) {
	if f.files[layer] != nil {
		return f.files[layer], nil
	}
	file, err := os.OpenFile(filepath.Join(f.path, fmt.Sprintf("layer_%d.bin", layer)), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("error opening file for layer %d: %w", layer, err)
	}
	f.files[layer] = file
	return file, nil
}

func (f *fileLayerCache) Append(layer uint, data []byte) error {
	file, err := f.openFile(layer)
	if err != nil {
		return fmt.Errorf("error opening file for layer %d: %w", layer, err)
	}

	// Write data to the file
	// TODO(mafa): consider using a buffered writer for better performance
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("error writing data to file for layer %d: %w", layer, err)
	}
	return nil
}

func (f *fileLayerCache) ReadAt(layer uint, index int) ([]byte, error) {
	file, err := f.openFile(layer)
	if err != nil {
		return nil, fmt.Errorf("error opening file for layer %d: %w", layer, err)
	}

	// Read data from the file at the specified index
	data := make([]byte, 32)                    // TODO(mafa): make this configurable
	_, err = file.ReadAt(data, int64(index*32)) // TODO(mafa): make the size configurable
	switch {
	case errors.Is(err, os.ErrInvalid):
		return nil, fmt.Errorf("index out of bounds for layer %d: %w", layer, err)
	case errors.Is(err, io.EOF):
		// If we reach EOF, it means we reached the end of the file.
		return data, err
	case err != nil:
		return nil, fmt.Errorf("error reading data from file for layer %d: %w", layer, err)
	}

	// Move to the end of the file, so that subsequent writes append to the end
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return data, fmt.Errorf("error seeking to end of file for layer %d: %w", layer, err)
	}
	return data, nil
}

func (f *fileLayerCache) Len(layer uint) (int, error) {
	file, err := f.openFile(layer)
	if err != nil {
		return 0, fmt.Errorf("error opening file for layer %d: %w", layer, err)
	}

	// Get the length of the file
	info, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("error getting file info for layer %d: %w", layer, err)
	}

	// Calculate the number of entries based on the file size and entry size (32 bytes)
	entrySize := 32 // TODO(mafa): make this configurable
	if info.Size()%int64(entrySize) != 0 {
		return 0, fmt.Errorf("file size for layer %d is not a multiple of entry size (%d bytes): %d bytes",
			layer, entrySize, info.Size(),
		)
	}
	numEntries := int(info.Size() / int64(entrySize))
	return numEntries, nil
}

func (f *fileLayerCache) Close() error {
	var errs error
	for layer, file := range f.files {
		if err := file.Close(); err != nil {
			errs = errors.Join(err, fmt.Errorf("error closing layer_%d.bin: %w", layer, err))
		}
	}
	return errs
}
