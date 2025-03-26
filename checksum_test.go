// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Test the checksum computation helpers using IPv4 packets
func TestChecksum(t *testing.T) {
	testData := []struct {
		name   string
		header string
		want   string
	}{{
		name:   "sum has two carries",
		header: "4540005800000000ff11ffff0aeb1d070aed8877",
		want:   "fffe",
	}, {
		name:   "wikipedia case",
		header: "45000073000040004011b861c0a80001c0a800c7",
		want:   "b861",
	}}

	for _, test := range testData {
		bytes, err := hex.DecodeString(test.header)
		if err != nil {
			t.Fatalf("Failed to Decode header: %v", err)
		}
		wantBytes, err := hex.DecodeString(test.want)
		if err != nil {
			t.Fatalf("Failed to decode want checksum: %v", err)
		}

		// Clear checksum bytes
		bytes[10] = 0
		bytes[11] = 0

		csum := ComputeChecksum(bytes, 0)
		if got, want := FoldChecksum(csum), binary.BigEndian.Uint16(wantBytes); got != want {
			t.Errorf("In test %q, got incorrect checksum: got(%x), want(%x)", test.name, got, want)
		}
	}
}
