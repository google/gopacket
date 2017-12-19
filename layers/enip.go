// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
)

const (
	enipMinPacketLen           int = 24
	enipMinRegSessionPacketLen int = 4
	enipMinSendRRDataPacketLen int = 36

	ENIP_TCPPort uint16 = 44818
	ENIP_UDPPort uint16 = 2222
)

var (
	listServices      enipCommand = 0x0004
	listIdentity      enipCommand = 0x0063
	listInterfaces    enipCommand = 0x0064
	registerSession   enipCommand = 0x0065
	unregisterSession enipCommand = 0x0066
	sendRRData        enipCommand = 0x006f
	sendUnitData      enipCommand = 0x0070

	ErrUnknownENIPCommand = errors.New("Unknown Ethernet/IP Command")
	ErrENIPDataTooSmall   = errors.New("ENIP packet data truncated")
)

type enipCommand uint16

type ENIP struct {
	BaseLayer
	Command         enipCommand
	Length          uint16
	SessionHandle   uint32
	Status          uint32
	SenderContext   [8]byte
	Options         uint32
	CommandSpecific ENIPCommandSpecificData
}

type ENIPCommandSpecificData struct {
	cmd  enipCommand
	data []byte
}

func init() {
	RegisterTCPPortLayerType(TCPPort(ENIP_TCPPort), LayerTypeENIP)
}

func (enip *ENIP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < enipMinPacketLen {
		df.SetTruncated()
		return ErrENIPDataTooSmall
	}
	enip.Command = enipCommand(binary.LittleEndian.Uint16(data[0:2]))
	enip.Length = binary.LittleEndian.Uint16(data[2:4])
	enip.SessionHandle = binary.LittleEndian.Uint32(data[4:8])
	enip.Status = binary.LittleEndian.Uint32(data[8:12])
	enip.SenderContext = enip.senderContext(data)
	enip.Options = binary.LittleEndian.Uint32(data[20:24])
	return enip.getPayload(data, df)
}

func (enip *ENIP) senderContext(data []byte) (sc [8]byte) {
	for i := 0; i < 8; i++ {
		sc[i] = data[i+12]
	}
	return
}

func (enip *ENIP) getPayload(data []byte, df gopacket.DecodeFeedback) (err error) {
	enip.CommandSpecific.cmd = enip.Command
	switch enip.Command {
	case registerSession: //register session
		if len(data) < enipMinRegSessionPacketLen {
			df.SetTruncated()
			err = ErrENIPDataTooSmall
			return
		}
		enip.CommandSpecific.data = data[24:28]
		enip.Contents = data[0:28]
		enip.Payload = data[28:]
	case sendUnitData:
		fallthrough
	case sendRRData:
		if len(data) < enipMinSendRRDataPacketLen {
			df.SetTruncated()
			return ErrENIPDataTooSmall
		}
		//grab the item count
		itemCount := int(binary.LittleEndian.Uint16(data[30:32]))
		csdEnd := 32
		for i := 0; i < itemCount; i++ {
			csdEnd += getDataFormatIdLen(binary.LittleEndian.Uint16(data[csdEnd:]), data[csdEnd+2:]) //get length
		}
		if len(data) < csdEnd {
			df.SetTruncated()
			return ErrENIPDataTooSmall
		}
		enip.CommandSpecific.data = data[24:csdEnd]
		enip.Contents = data[0:csdEnd]
		enip.Payload = data[csdEnd:]
	default:
		enip.CommandSpecific.data = data[24:]
		enip.Contents = data
		enip.Payload = []byte{}
	}
	return
}

func getDataFormatIdLen(id uint16, data []byte) int {
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

func (enip *ENIP) LayerType() gopacket.LayerType { return LayerTypeENIP }
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

func (csd ENIPCommandSpecificData) NextLayer() (nl gopacket.LayerType) {
	if len(csd.data) < 4 {
		nl = gopacket.LayerTypePayload
		return
	}
	switch binary.LittleEndian.Uint32(csd.data) {
	case 0x0:
		nl = LayerTypeCIP
	default:
		nl = gopacket.LayerTypePayload
	}
	return
}
