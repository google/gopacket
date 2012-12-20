// Copyright 2012, Google, Inc. All rights reserved.

// This file contains some test helper functions.

package layers

import (
	"github.com/gconnell/gopacket"
	"testing"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func checkLayers(p gopacket.Packet, want []gopacket.LayerType, t *testing.T) {
	layers := p.Layers()
	t.Log("Checking packet layers, want", want)
	for _, l := range layers {
		t.Logf("  Got layer %v, %d bytes, payload of %d bytes", l.LayerType(), len(l.LayerContents()), len(l.LayerPayload()))
	}
	if len(layers) != len(want) {
		t.Errorf("  Number of layers mismatch: got %d want %d", len(want), len(layers))
		return
	}
	for i, l := range layers {
		if l.LayerType() != want[i] {
			t.Errorf("  Layer %d mismatch: got %v want %v", i, l.LayerType(), want[i])
		}
	}
}
