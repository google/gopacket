// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

// LayerClass is a set of LayerTypes, used for grabbing one of a number of
// different types from a packet.
type LayerClass interface {
	// Contains returns true if the given layer type should be considered part
	// of this layer class.
	Contains(LayerType) bool
}

// LayerClassSlice implements a LayerClass with a slice.
type LayerClassSlice []bool

// Contains returns true if the given layer type should be considered part
// of this layer class.
func (s LayerClassSlice) Contains(t LayerType) bool {
	return int(t) < len(s) && s[t]
}

// NewLayerClassSlice creates a new LayerClassSlice by creating a slice of
// size max(types) and setting slice[t] to true for each type t.  Note, if
// you implement your own LayerType and give it a high value, this WILL create
// a very large slice.
func NewLayerClassSlice(types []LayerType) LayerClassSlice {
	var max LayerType
	for _, typ := range types {
		if typ > max {
			max = typ
		}
	}
	t := make([]bool, int(max+1))
	for typ := range types {
		t[typ] = true
	}
	return t
}

// LayerClassMap implements a LayerClass with a map.
type LayerClassMap map[LayerType]bool

// Contains returns true if the given layer type should be considered part
// of this layer class.
func (m LayerClassMap) Contains(t LayerType) bool {
	return m[t]
}

// NewLayerClassMap creates a LayerClassMap and sets map[t] to true for each
// type in types.
func NewLayerClassMap(types []LayerType) LayerClassMap {
	m := LayerClassMap{}
	for _, typ := range types {
		m[typ] = true
	}
	return m
}

// NewLayerClass creates a LayerClass, attempting to be smart about which type
// it creates based on which types are passed in.
func NewLayerClass(types []LayerType) LayerClass {
	for _, typ := range types {
		if typ > maxLayerType {
			// NewLayerClassSlice could create a very large object, so instead create
			// a map.
			return NewLayerClassMap(types)
		}
	}
	return NewLayerClassSlice(types)
}
