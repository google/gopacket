package layers

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
)

type GTPExtenstionHeader struct {
	Type    uint8
	Content []byte
}

// GTPV1U protocol is used to exchange user data over GTP tunnels across the Sx interfaces.
// Defined in https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1595
type GTPv1U struct {
	BaseLayer
	Version             uint8
	ProtocolType        uint8
	Reserved            uint8
	ExtensionHeaderFlag bool
	SequenceNumberFlag  bool
	NPDUFlag            bool
	MessageType         uint8
	MessageLength       uint16
	TEID                uint32
	SequenceNumber      uint16
	NPDU                uint8
	GTPExtensionHeaders []GTPExtenstionHeader
}

// LayerType returns LayerTypeGTPV1U
func (g *GTPv1U) LayerType() gopacket.LayerType { return LayerTypeGTPv1U }

func (gtp *GTPv1U) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	hLen := 8
	if len(data) < hLen {
		return fmt.Errorf("GTP packet too small: %d bytes", len(data))
	}
	gtp.Version = (data[0] >> 5) & 0x07
	gtp.ProtocolType = (data[0] >> 4) & 0x01
	gtp.Reserved = (data[0] >> 3) & 0x01
	gtp.SequenceNumberFlag = ((data[0] >> 1) & 0x01) == 1
	gtp.NPDUFlag = (data[0] & 0x01) == 1
	gtp.ExtensionHeaderFlag = ((data[0] >> 2) & 0x01) == 1
	gtp.MessageType = data[1]
	gtp.MessageLength = binary.BigEndian.Uint16(data[2:4])
	pLen := 8 + gtp.MessageLength
	if uint16(len(data)) < pLen {
		return fmt.Errorf("GTP packet too small: %d bytes", len(data))
	}
	//  Field used to multiplex different connections in the same GTP tunnel.
	gtp.TEID = binary.BigEndian.Uint32(data[4:8])
	if gtp.SequenceNumberFlag || gtp.NPDUFlag || gtp.ExtensionHeaderFlag {
		hLen += 4
		if uint16(len(data)) < pLen {
			return fmt.Errorf("GTP packet too small: %d bytes", len(data))
		}
		if gtp.SequenceNumberFlag {
			gtp.SequenceNumber = binary.BigEndian.Uint16(data[8:10])
		}
		if gtp.NPDUFlag {
			gtp.NPDU = data[10]
		}
		cIndex := uint(hLen)
		if gtp.ExtensionHeaderFlag {
			extensionFlag := true
			for extensionFlag {
				extensionLength := uint(data[cIndex-1])
				if extensionLength == 0 || extensionLength%4 != 0 {
					return fmt.Errorf("GTP packet with invalid extension header")
				}
				lIndex := cIndex + extensionLength/8
				content := data[cIndex+1 : lIndex-1]
				eh := GTPExtenstionHeader{Type: data[lIndex], Content: content}
				gtp.GTPExtensionHeaders = append(gtp.GTPExtensionHeaders, eh)
				if eh.Type == 0 {
					extensionFlag = false
				}
				cIndex = lIndex + 1

			}
		}
		gtp.BaseLayer = BaseLayer{Contents: data[:cIndex], Payload: data[cIndex:]}
	}
	return nil

}

func (g *GTPv1U) CanDecode() gopacket.LayerClass {
	return LayerTypeGTPv1U
}

func (g *GTPv1U) NextLayerType() gopacket.LayerType {
	return LayerTypeIPv4
}

func decodeGTPv1u(data []byte, p gopacket.PacketBuilder) error {
	gtp := &GTPv1U{}
	err := gtp.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(gtp)
	return p.NextDecoder(gtp.NextLayerType())
}
