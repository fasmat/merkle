package ordered_test

import (
	"slices"
	"testing"

	"github.com/fasmat/merkle/internal/ordered"
)

func TestMap(t *testing.T) {
	t.Parallel()

	// Create a new map
	data := make(map[int]string)

	// Add some key-value pairs
	data[3] = "three"
	data[1] = "one"
	data[2] = "two"

	// Create an ordered map from the data
	om := ordered.MapFrom(data)

	// Check the length of the map
	if om.Len() != len(data) {
		t.Errorf("expected length %d, got %d", len(data), om.Len())
	}

	keys := om.Keys()
	values := om.Values()

	if !slices.IsSorted(keys) {
		t.Errorf("keys are not sorted: %v", keys)
	}

	if len(keys) != len(values) {
		t.Errorf("keys and values lengths do not match: %d vs %d", len(keys), len(values))
	}

	// Check values match keys
	for i, key := range keys {
		val, ok := om.Value(key)
		if !ok {
			t.Errorf("key %d not found in map", key)
			continue
		}
		if data[key] != val {
			t.Errorf("value for key %d does not match: expected %s, got %s", key, data[key], values[i])
		}
	}
}

func TestMapAll(t *testing.T) {
	t.Parallel()

	// Create a new map
	data := make(map[int]string)

	// Add some key-value pairs
	data[3] = "three"
	data[1] = "one"
	data[2] = "two"

	// Create an ordered map from the data
	om := ordered.MapFrom(data)

	keys := om.Keys()
	values := om.Values()

	// Check all iteration
	for key, value := range om.All() {
		if key != keys[0] {
			t.Errorf("expected key %d, got %d", keys[0], key)
		}
		if value != values[0] {
			t.Errorf("expected value %s, got %s", values[0], value)
		}
		keys = keys[1:]
		values = values[1:]
	}

	// Check if all keys and values are iterated
	if len(keys) != 0 {
		t.Errorf("not all keys were iterated: %v", keys)
	}
	if len(values) != 0 {
		t.Errorf("not all values were iterated: %v", values)
	}
}
