package layers

import (
	"encoding/binary"
	"unsafe"
)

// ReadUint8 reads a Uint8 value from specified slice and returns
// the resulting slice and boolean flag telling if it was a success.
//
// Value is treated as big endian.
func ReadUint8(data []byte, x *uint8) ([]byte, bool) {
	if len(data) >= 1 {
		*x = data[0]
		return data[1:], true
	}

	return nil, false
}

// BeReadUint16 reads a Uint16 value from specified slice and returns
// the resulting slice and boolean flag telling if it was a success.
//
// Value is treated as big endian.
func BeReadUint16(data []byte, x *uint16) ([]byte, bool) {
	if d := int(unsafe.Sizeof(*x)); len(data) >= d {
		*x = binary.BigEndian.Uint16(data)
		return data[d:], true
	}

	return nil, false
}

// BeReadUint32 reads a Uint32 value from specified slice and returns
// the resulting slice and boolean flag telling if it was a success.
//
// Value is treated as big endian.
func BeReadUint32(data []byte, x *uint32) ([]byte, bool) {
	if d := int(unsafe.Sizeof(*x)); len(data) >= d {
		*x = binary.BigEndian.Uint32(data)
		return data[d:], true
	}

	return nil, false
}

// BeReadUint64 reads a Uint64 value from specified slice and returns
// the resulting slice and boolean flag telling if it was a success.
//
// Value is treated as big endian.
func BeReadUint64(data []byte, x *uint64) ([]byte, bool) {
	if d := int(unsafe.Sizeof(*x)); len(data) >= d {
		*x = binary.BigEndian.Uint64(data)
		return data[d:], true
	}

	return nil, false
}

// ReadBytes checks if data has n bytes at the top and puts them into
// x. Returns the resulting slice and true if reslicing was
// successful.
func ReadBytes(data []byte, x *[]byte, n int) ([]byte, bool) {
	if len(data) >= n {
		*x = data[:n]
		return data[n:], true
	}

	return nil, false
}

// CopyBytes copies up to len(x) bytes from the top of data to x.
// Returns the resulting slice and true if len(x) bytes were copied.
func CopyBytes(data []byte, x []byte) ([]byte, bool) {
	n := copy(x, data)
	return data[n:], len(x) == n
}

// SkipBytes skips n bytes in data, returning resulting slice and true
// if data had at least n bytes.
func SkipBytes(data []byte, n int) ([]byte, bool) {
	if n <= len(data) {
		return data[n:], true
	}
	return nil, false
}
