// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
)

// IPv4 is the header of an IP packet.
type IPv4 struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	Id         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   IPProtocol
	Checksum   uint16
	SrcIP      []byte
	DstIP      []byte
}

// LayerType returns LayerTypeIPv4
func (i *IPv4) LayerType() LayerType { return LayerTypeIPv4 }
func (i *IPv4) NetFlow() Flow {
	return Flow{LayerTypeIPv4, string(i.SrcIP), string(i.DstIP)}
}

var decodeIPv4 decoderFunc = func(data []byte) (out DecodeResult, err error) {
	flagsfrags := binary.BigEndian.Uint16(data[6:8])
	ip := &IPv4{
		Version:    uint8(data[0]) >> 4,
		IHL:        uint8(data[0]) & 0x0F,
		TOS:        data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
		Id:         binary.BigEndian.Uint16(data[4:6]),
		Flags:      uint8(flagsfrags >> 13),
		FragOffset: flagsfrags & 0x1FFF,
		TTL:        data[8],
		Protocol:   IPProtocol(data[9]),
		Checksum:   binary.BigEndian.Uint16(data[10:12]),
		SrcIP:      data[12:16],
		DstIP:      data[16:20],
	}
	pEnd := int(ip.Length)
	if pEnd > len(data) {
		pEnd = len(data)
	}
	out.RemainingBytes = data[ip.IHL*4 : pEnd]
	out.DecodedLayer = ip
	out.NextDecoder = ip.Protocol
	out.NetworkLayer = ip
	return
}
