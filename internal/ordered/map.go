package ordered

import (
	"cmp"
	"iter"
	"maps"
	"slices"
)

// Map is a map that maintains the order of keys based on their natural ordering
type Map[K cmp.Ordered, V any] struct {
	// The map to store the key-value pairs
	data map[K]V

	// Slice to store the keys in sorted order
	keys []K
}

// MapFrom creates a new ordered.Map from the given map
func MapFrom[K cmp.Ordered, V any](data map[K]V) Map[K, V] {
	keys := slices.Collect(maps.Keys(data))
	slices.Sort(keys)

	return Map[K, V]{
		data: maps.Clone(data),
		keys: keys,
	}
}

// Value retrieves the value for a given key
func (om Map[K, V]) Value(key K) (V, bool) {
	value, exists := om.data[key]
	return value, exists
}

// Keys returns the keys in sorted order
func (om Map[K, V]) Keys() []K {
	return om.keys
}

// Values returns the values in the order of the sorted keys
func (om Map[K, V]) Values() []V {
	values := make([]V, len(om.keys))
	for i, key := range om.keys {
		values[i] = om.data[key]
	}
	return values
}

// Len returns the number of key-value pairs in the map
func (om Map[K, V]) Len() int {
	return len(om.keys)
}

// All returns an iterable sequence of all key-value pairs
func (om Map[K, V]) All() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for _, key := range om.keys {
			if !yield(key, om.data[key]) {
				return
			}
		}
	}
}
