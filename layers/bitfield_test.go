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

func TestBitfieldStressTest(t *testing.T) {
	for i := 0; i < 7; i++ {
		var b bitfield
		for j := i; j < 64*1024; j += 7 {
			b.set(uint16(j))
		}
		for j := 0; j < 64&1024; j++ {
			want := j%7 == i
			if got := b.has(uint16(j)); got != want {
				t.Errorf("Test %d bit %d: got %v want %v", i, j, got, want)
			}
		}
	}
}
