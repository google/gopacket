package assembly

import (
	"reflect"
	"testing"
)

type testSequence struct {
	in   TCP
	want []Reassembly
}

type testFactory struct {
	reassembly []Reassembly
}

func (t *testFactory) New(k Key) Stream {
	return t
}
func (t *testFactory) Reassembled(r []Reassembly) {
	t.reassembly = r
}
func (t *testFactory) ReassemblyComplete() {
}

func test(t *testing.T, s []testSequence) {
	fact := &testFactory{}
	p := NewConnectionPool(fact)
	a := NewAssembler(100, 4, 1000, p)
	for i, test := range s {
		fact.reassembly = []Reassembly{}
		a.Assemble(&test.in)
		if !reflect.DeepEqual(fact.reassembly, test.want) {
			t.Fatalf("test %v:\nwant: %v\n got: %v\n", i, test.want, fact.reassembly)
		}
	}
}

var key1 = Key{
	Version: 4,
	SrcIP:   [...]byte{1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	DstIP:   [...]byte{5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	SrcPort: 0,
	DstPort: 0,
}

func TestReorder(t *testing.T) {
	test(t, []testSequence{
		{
			in: TCP{
				Key:   key1,
				Seq:   1001,
				Bytes: []byte{1, 2, 3},
			},
			want: []Reassembly{},
		},
		{
			in: TCP{
				Key:   key1,
				Seq:   1004,
				Bytes: []byte{2, 2, 3},
			},
			want: []Reassembly{},
		},
		{
			in: TCP{
				Key:   key1,
				Seq:   1010,
				Bytes: []byte{4, 2, 3},
			},
			want: []Reassembly{},
		},
		{
			in: TCP{
				Key:   key1,
				Seq:   1007,
				Bytes: []byte{3, 2, 3},
			},
			want: []Reassembly{
				Reassembly{
					Seq:   1001,
					Skip:  true,
					Bytes: []byte{1, 2, 3},
				},
				Reassembly{
					Seq:   1004,
					Skip:  false,
					Bytes: []byte{2, 2, 3},
				},
				Reassembly{
					Seq:   1007,
					Skip:  false,
					Bytes: []byte{3, 2, 3},
				},
				Reassembly{
					Seq:   1010,
					Skip:  false,
					Bytes: []byte{4, 2, 3},
				},
			},
		},
	})
}

func TestReorderFast(t *testing.T) {
	test(t, []testSequence{
		{
			in: TCP{
				Key:   key1,
				SYN:   true,
				Seq:   1000,
				Bytes: []byte{1, 2, 3},
			},
			want: []Reassembly{
				Reassembly{
					Start: true,
					Skip:  false,
					Bytes: []byte{1, 2, 3},
					Seq:   1000,
				},
			},
		},
		{
			in: TCP{
				Key:   key1,
				Seq:   1007,
				Bytes: []byte{3, 2, 3},
			},
			want: []Reassembly{},
		},
		{
			in: TCP{
				Key:   key1,
				Seq:   1004,
				Bytes: []byte{2, 2, 3},
			},
			want: []Reassembly{
				Reassembly{
					Skip:  false,
					Bytes: []byte{2, 2, 3},
					Seq:   1004,
				},
				Reassembly{
					Skip:  false,
					Bytes: []byte{3, 2, 3},
					Seq:   1007,
				},
			},
		},
	})
}

func TestOverlap(t *testing.T) {
	test(t, []testSequence{
		{
			in: TCP{
				Key:   key1,
				SYN:   true,
				Seq:   1000,
				Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
			},
			want: []Reassembly{
				Reassembly{
					Skip:  false,
					Start: true,
					Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
					Seq:   1000,
				},
			},
		},
		{
			in: TCP{
				Key:   key1,
				Seq:   1007,
				Bytes: []byte{7, 8, 9, 0, 1, 2, 3, 4},
			},
			want: []Reassembly{
				Reassembly{
					Skip:  false,
					Bytes: []byte{1, 2, 3, 4},
					Seq:   1011,
				},
			},
		},
	})
}

func TestOverrun1(t *testing.T) {
	test(t, []testSequence{
		{
			in: TCP{
				Key:   key1,
				SYN:   true,
				Seq:   0xFFFFFFFF,
				Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
			},
			want: []Reassembly{
				Reassembly{
					Skip:  false,
					Start: true,
					Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
					Seq:   0xFFFFFFFF,
				},
			},
		},
		{
			in: TCP{
				Key:   key1,
				Seq:   10,
				Bytes: []byte{1, 2, 3, 4},
			},
			want: []Reassembly{
				Reassembly{
					Skip:  false,
					Bytes: []byte{1, 2, 3, 4},
					Seq:   10,
				},
			},
		},
	})
}

func TestOverrun2(t *testing.T) {
	test(t, []testSequence{
		{
			in: TCP{
				Key:   key1,
				Seq:   10,
				Bytes: []byte{1, 2, 3, 4},
			},
			want: []Reassembly{},
		},
		{
			in: TCP{
				Key:   key1,
				SYN:   true,
				Seq:   0xFFFFFFFF,
				Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
			},
			want: []Reassembly{
				Reassembly{
					Skip:  false,
					Start: true,
					Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
					Seq:   0xFFFFFFFF,
				},
				Reassembly{
					Skip:  false,
					Bytes: []byte{1, 2, 3, 4},
					Seq:   10,
				},
			},
		},
	})
}

func BenchmarkSingleStream(b *testing.B) {
	t := TCP{
		Key:   key1,
		SYN:   true,
		Seq:   1000,
		Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
	}
	a := NewAssembler(100, 4, 1000, NewConnectionPool(&testFactory{}))
	for i := 0; i < b.N; i++ {
		a.Assemble(&t)
		if t.SYN {
			t.SYN = false
			t.Seq++
		}
		t.Seq += 10
	}
}

func BenchmarkSingleStreamSkips(b *testing.B) {
	t := TCP{
		Key:   key1,
		SYN:   true,
		Seq:   1000,
		Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
	}
	a := NewAssembler(100, 10, 1000, NewConnectionPool(&testFactory{}))
	skipped := false
	for i := 0; i < b.N; i++ {
		if i%10 == 9 {
			t.Seq += 10
			skipped = true
		} else if skipped {
			t.Seq -= 20
		}
		a.Assemble(&t)
		if t.SYN {
			t.SYN = false
			t.Seq++
		}
		t.Seq += 10
		if skipped {
			t.Seq += 10
			skipped = false
		}
	}
}

func BenchmarkSingleStreamLoss(b *testing.B) {
	t := TCP{
		Key:   key1,
		SYN:   true,
		Seq:   1000,
		Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
	}
	a := NewAssembler(100, 10, 1000, NewConnectionPool(&testFactory{}))
	for i := 0; i < b.N; i++ {
		a.Assemble(&t)
		t.SYN = false
		t.Seq += 11
	}
}

func BenchmarkMultiStreamGrow(b *testing.B) {
	t := TCP{
		Key:   key1,
		Seq:   0,
		Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
	}
	a := NewAssembler(1000000, 10, 1000, NewConnectionPool(&testFactory{}))
	for i := 0; i < b.N; i++ {
		t.Key.SrcPort = uint16(i)
		a.Assemble(&t)
		t.Seq += 10
	}
}

func BenchmarkMultiStreamConn(b *testing.B) {
	t := TCP{
		Key:   key1,
		Seq:   0,
		SYN:   true,
		Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
	}
	a := NewAssembler(1000000, 10, 1000, NewConnectionPool(&testFactory{}))
	for i := 0; i < b.N; i++ {
		t.Key.SrcPort = uint16(i)
		a.Assemble(&t)
		if i%65536 == 65535 {
			if t.SYN {
				t.SYN = false
				t.Seq += 1
			}
			t.Seq += 10
		}
	}
}
