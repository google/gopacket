package layers

import (
	"encoding/binary"
	"unsafe"
)

var endian binary.ByteOrder = _endian()

// _endian returns the binary.ByteOrder as defined for the host byte order
func _endian() binary.ByteOrder {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		return binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		return binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}
