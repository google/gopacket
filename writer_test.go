package gopacket

import (
	"fmt"
	"testing"
)

func TestExponentialSizeIncreasePrepend(t *testing.T) {
	var b SerializeBuffer
	for i, test := range []struct {
		prepend, size int
	}{
		{2, 2},
		{2, 4},
		{2, 8},
		{2, 8},
		{2, 16},
		{2, 16},
		{2, 16},
		{2, 16},
		{2, 32},
	} {
		b.PrependBytes(test.prepend)
		if test.size != cap(b.data) {
			t.Error(i, "size want", test.size, "got", cap(b.data))
		}
	}
	b.Clear()
	if b.start != 32 {
		t.Error(b.start)
	}
}

func TestExponentialSizeIncreaseAppend(t *testing.T) {
	var b SerializeBuffer
	for i, test := range []struct {
		appnd, size int
	}{
		{2, 2},
		{2, 4},
		{2, 8},
		{2, 8},
		{2, 16},
		{2, 16},
		{2, 16},
		{2, 16},
		{2, 32},
	} {
		b.AppendBytes(test.appnd)
		if test.size != cap(b.data) {
			t.Error(i, "size want", test.size, "got", cap(b.data))
		}
	}
	b.Clear()
	if b.start != 0 {
		t.Error(b.start)
	}
}

func ExampleSerializeBuffer() {
	var b SerializeBuffer
	fmt.Println("1:", b.Bytes())
	copy(b.PrependBytes(3), []byte{1, 2, 3})
	fmt.Println("2:", b.Bytes())
	copy(b.AppendBytes(2), []byte{4, 5})
	fmt.Println("3:", b.Bytes())
	copy(b.PrependBytes(1), []byte{0})
	fmt.Println("4:", b.Bytes())
	copy(b.AppendBytes(3), []byte{6, 7, 8})
	fmt.Println("5:", b.Bytes())
	b.Clear()
	fmt.Println("6:", b.Bytes())
	copy(b.PrependBytes(2), []byte{9, 9})
	fmt.Println("7:", b.Bytes())
	// Output:
	// 1: []
	// 2: [1 2 3]
	// 3: [1 2 3 4 5]
	// 4: [0 1 2 3 4 5]
	// 5: [0 1 2 3 4 5 6 7 8]
	// 6: []
	// 7: [9 9]
}
