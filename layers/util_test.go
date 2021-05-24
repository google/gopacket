package layers

import (
	"bytes"
	"testing"
)

func TestBeRead(t *testing.T) {
	data := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}

	{
		var x []byte
		res, ok := ReadBytes(data, &x, 4)
		assert(t, ok)
		assert(t, bytes.Equal(x, []byte{0xaa, 0xbb, 0xcc, 0xdd}))
		assert(t, bytes.Equal(res, []byte{0x11, 0x22, 0x33, 0x44}))
	}

	{
		x := uint8(0)
		res, ok := ReadUint8(data, &x)
		assert(t, ok)
		assert(t, bytes.Equal(res, []byte{0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}))
		assert(t, x == 0xaa)
	}

	{
		x := uint16(0)
		res, ok := BeReadUint16(data, &x)
		assert(t, ok)
		assert(t, bytes.Equal(res, []byte{0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}))
		assert(t, x == 0xaabb)
	}

	{
		x := uint32(0)
		res, ok := BeReadUint32(data, &x)
		assert(t, ok)
		assert(t, bytes.Equal(res, []byte{0x11, 0x22, 0x33, 0x44}))
		assert(t, x == 0xaabbccdd)

		y := uint64(0)
		res, ok = BeReadUint64(res, &y)
		assert(t, !ok)
	}

	{
		x := uint64(0)
		res, ok := BeReadUint64(data, &x)
		assert(t, ok)
		assert(t, bytes.Equal(res, []byte{}))
		assert(t, x == 0xaabbccdd11223344)
	}
}
