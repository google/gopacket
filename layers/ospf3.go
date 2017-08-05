import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
)

// OSPFv3 is a OSPF Version 3 packet header.
type OSPFv3 struct {
	BaseLayer
	Version           uint8
	Type              uint8
	PacketLength      uint16
	RouterID          uint32
	AreaID            uint32
	Checksum          uint16
	Instance          uint8
	Reserved          uint8
}


func decodeOSPFv3(data []byte, p gopacket.PacketBuilder) error {
	ospf := &OSPFv3{}
	return decodingLayerDecoder(ospf, data, p)
}
