// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"fmt"
)

// ICMP is the layer for ICMP packet data.
type ICMP struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Id       uint16
	Seq      uint16
}

// LayerType returns LayerTypeICMP
func (i *ICMP) LayerType() LayerType { return LayerTypeICMP }

func decodeICMP(data []byte) (out DecodeResult, err error) {
	out.DecodedLayer = &ICMP{
		Type:     data[0],
		Code:     data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
		Id:       binary.BigEndian.Uint16(data[4:6]),
		Seq:      binary.BigEndian.Uint16(data[6:8]),
	}
	out.RemainingBytes = data[8:]
	out.NextDecoder = decodePayload
	return
}

func (icmp *ICMP) TypeString() (result string) {
	switch icmp.Type {
	case 0:
		result = fmt.Sprintf("Echo reply seq=%d", icmp.Seq)
	case 3:
		switch icmp.Code {
		case 0:
			result = "Network unreachable"
		case 1:
			result = "Host unreachable"
		case 2:
			result = "Protocol unreachable"
		case 3:
			result = "Port unreachable"
		default:
			result = "Destination unreachable"
		}
	case 8:
		result = fmt.Sprintf("Echo request seq=%d", icmp.Seq)
	case 30:
		result = "Traceroute"
	}
	return
}
