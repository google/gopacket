package layers

import "testing"

func TestBitfield(t *testing.T) {
	var b bitfield

	const uint16Max = ^uint16(0)

	for i := uint16(0); i < uint16Max; i++ {
		if b.has(i) {
			t.Errorf("b.has(%d) expected false, got true", i)
		}
	}

	b.set(0)
	if !b.has(0) {
		t.Error("b.has(0) expected true, got false")
	}

	for i := uint16(1); i < uint16Max; i++ {
		if b.has(i) {
			t.Errorf("b.has(%d) expected false, got true", i)
		}
	}
}
