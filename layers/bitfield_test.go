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

	set := []uint16{0, 64 * 3, 64*3 + 12, 64*3 + 63, uint16Max}
	for _, s := range set {
		b.set(s)
	}

	for i := uint16(0); i < uint16Max; i++ {
		wantSet := false
		for _, s := range set {
			if i == s {
				wantSet = true
				break
			}
		}

		if wantSet {
			if !b.has(i) {
				t.Errorf("b.has(%d) expected true, got false", i)
			}
		} else {
			if b.has(i) {
				t.Errorf("b.has(%d) expected false, got true", i)
			}

		}
	}
}
