// Copyright 2012, Google, Inc. All rights reserved.

package gopacket

import (
	"testing"
)

// A few benchmarks for figuring out exactly how fast some underlying Go
// things are.

type testError struct{}

func (t *testError) Error() string { return "abc" }

func BenchmarkTypeAssertion(b *testing.B) {
	var e error = &testError{}
	for i := 0; i < b.N; i++ {
		_, _ = e.(*testError)
	}
}

func BenchmarkMapLookup(b *testing.B) {
	m := map[LayerType]bool{
		LayerTypePayload: true,
	}
	for i := 0; i < b.N; i++ {
		_ = m[LayerTypePayload]
	}
}

func BenchmarkNilMapLookup(b *testing.B) {
	var m map[LayerType]bool
	for i := 0; i < b.N; i++ {
		_ = m[LayerTypePayload]
	}
}

func BenchmarkNilMapLookupWithNilCheck(b *testing.B) {
	var m map[LayerType]bool
	for i := 0; i < b.N; i++ {
		if m != nil {
			_ = m[LayerTypePayload]
		}
	}
}

func BenchmarkArrayLookup(b *testing.B) {
	m := make([]bool, 100)
	for i := 0; i < b.N; i++ {
		_ = m[LayerTypePayload]
	}
}

var testError1 = &testError{}
var testError2 error = testError1

func BenchmarkTypeToInterface1(b *testing.B) {
	var e error
	for i := 0; i < b.N; i++ {
		e = testError1
	}
	// Have to do someting with 'e' or the compiler complains about an unused
	// variable.
	testError2 = e
}
func BenchmarkTypeToInterface2(b *testing.B) {
	var e error
	for i := 0; i < b.N; i++ {
		e = testError2
	}
	// Have to do someting with 'e' or the compiler complains about an unused
	// variable.
	testError2 = e
}

func BenchmarkCheckEthernetPrefix(b *testing.B) {
	key := [3]byte{5, 5, 5}
	for i := 0; i < b.N; i++ {
		_ = ValidMACPrefixMap[key]
	}
}
