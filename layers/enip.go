// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"

	"github.com/dreadl0ck/gopacket"
)

const (
	enipMinPacketLen           int = 24
	enipMinRegSessionPacketLen int = 4
	enipMinSendRRDataPacketLen int = 36

	// TCPPortENIP is the TCP port used to transport EtherNet/IP packets
	TCPPortENIP uint16 = 44818
	// UDPPortENIP is the UDP port used to transport EtherNet/IP packets
	UDPPortENIP uint16 = 2222
)

var (
	listServices      ENIPCommand = 0x0004
	listIdentity      ENIPCommand = 0x0063
	listInterfaces    ENIPCommand = 0x0064
	registerSession   ENIPCommand = 0x0065
	unregisterSession ENIPCommand = 0x0066
	sendRRData        ENIPCommand = 0x006f
	sendUnitData      ENIPCommand = 0x0070

	// ErrUnknownENIPCommand is returned if an invalid EtherNet/IP command is received
	ErrUnknownENIPCommand = errors.New("Unknown Ethernet/IP Command")
	// ErrENIPDataTooSmall is returned if an EtherNet/IP packet is truncated
	ErrENIPDataTooSmall = errors.New("ENIP packet data truncated")
)

// ENIPCommand is an EtherNet/IP command code
type ENIPCommand uint16

// ENIP implements decoding of EtherNet/IP, a protocol used to transport the
// Common Industrial Protocol over standard OSI networks. EtherNet/IP transports
// over both TCP and UDP.
// See the EtherNet/IP Developer's Guide for more information: https://www.odva.org/Portals/0/Library/Publications_Numbered/PUB00213R0_EtherNetIP_Developers_Guide.pdf
type ENIP struct {
	BaseLayer
	Command         ENIPCommand
	Length          uint16
	SessionHandle   uint32
	Status          uint32
	SenderContext   []byte
	Options         uint32
	CommandSpecific ENIPCommandSpecificData
}

// ENIPCommandSpecificData contains data specific to a command. This may
// include another EtherNet/IP packet embedded within the Data structure.
type ENIPCommandSpecificData struct {
	Cmd  ENIPCommand
	Data []byte
}

func init() {
	RegisterTCPPortLayerType(TCPPort(TCPPortENIP), LayerTypeENIP)
}

// DecodeFromBytes parses the contents of `data` as an EtherNet/IP packet.
func (enip *ENIP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < enipMinPacketLen {
		df.SetTruncated()
		return ErrENIPDataTooSmall
	}
	enip.Command = ENIPCommand(binary.LittleEndian.Uint16(data[0:2]))
	enip.Length = binary.LittleEndian.Uint16(data[2:4])
	enip.SessionHandle = binary.LittleEndian.Uint32(data[4:8])
	enip.Status = binary.LittleEndian.Uint32(data[8:12])
	enip.SenderContext = data[12:20]
	enip.Options = binary.LittleEndian.Uint32(data[20:24])
	return enip.getPayload(data, df)
}

func (enip *ENIP) getPayload(data []byte, df gopacket.DecodeFeedback) (err error) {
	enip.CommandSpecific.Cmd = enip.Command
	switch enip.Command {
	case registerSession: //register session
		if len(data) < enipMinRegSessionPacketLen {
			df.SetTruncated()
			err = ErrENIPDataTooSmall
			return
		}
		enip.CommandSpecific.Data = data[24:28]
		enip.Contents = data[0:28]
		enip.Payload = data[28:]
	case sendUnitData, sendRRData:
		if len(data) < enipMinSendRRDataPacketLen {
			df.SetTruncated()
			return ErrENIPDataTooSmall
		}
		//grab the item count
		itemCount := int(binary.LittleEndian.Uint16(data[30:32]))
		csdEnd := 32
		for i := 0; i < itemCount; i++ {
			csdEnd += getDataFormatIDLen(binary.LittleEndian.Uint16(data[csdEnd:]), data[csdEnd+2:]) //get length
		}
		if len(data) < csdEnd {
			df.SetTruncated()
			return ErrENIPDataTooSmall
		}
		enip.CommandSpecific.Data = data[24:csdEnd]
		enip.Contents = data[0:csdEnd]
		enip.Payload = data[csdEnd:]
	default:
		enip.CommandSpecific.Data = data[24:]
		enip.Contents = data
		enip.Payload = []byte{}
	}
	return
}

func getDataFormatIDLen(id uint16, data []byte) int {
	switch id {
	case 0x0000:
		return 4 //ID plus length of zero
	case 0x000C:
		return 8
	case 0x00A1:
		return 4 + int(binary.LittleEndian.Uint16(data))
	case 0x00B1:
		return 6
	case 0x00B2:
		return 4 //ID plus length
	case 0x0100:
		return 4 //ID plus length
	case 0x8000:
		return 4 //ID plus length
	case 0x8001:
		return 2 //ID plus length
	case 0x8002:
		return 2 //ID plus length
	}
	return 0
}

func (enip *ENIP) getInterfaceHandleNextProto(interfaceHandle uint32) gopacket.LayerType {
	switch interfaceHandle {
	case 0: //CIP
		return LayerTypeCIP
	}
	return gopacket.LayerTypePayload
}

// LayerType returns LayerTypeENIP
func (enip *ENIP) LayerType() gopacket.LayerType { return LayerTypeENIP }

// CanDecode returns LayerTypeENIP
func (enip *ENIP) CanDecode() gopacket.LayerClass { return LayerTypeENIP }

// NextLayerType returns either LayerTypePayload or the next layer type
// derived from the command specific data
func (enip *ENIP) NextLayerType() (nl gopacket.LayerType) {
	switch enip.Command {
	case sendRRData:
		fallthrough
	case sendUnitData:
		nl = enip.CommandSpecific.NextLayer()
	case registerSession:
		fallthrough
	default:
		nl = gopacket.LayerTypePayload
	}
	return
}

func decodeENIP(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < enipMinPacketLen {
		p.SetTruncated()
		return ErrENIPDataTooSmall
	}
	enip := &ENIP{}
	return decodingLayerDecoder(enip, data, p)
}

// NextLayer derives the next layer type by checking for a CIP marker
// at the start of the command specific data, returning LayerTypeCip
// if found; if not present, the next layer type is LayerTypePayload
func (csd ENIPCommandSpecificData) NextLayer() (nl gopacket.LayerType) {
	if len(csd.Data) < 4 {
		nl = gopacket.LayerTypePayload
		return
	}
	switch binary.LittleEndian.Uint32(csd.Data) {
	case 0x0:
		nl = LayerTypeCIP
	default:
		nl = gopacket.LayerTypePayload
	}
	return
}
