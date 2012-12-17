// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package layers

import (
	"encoding/binary"
	"github.com/gconnell/gopacket"
)

// IPv6 is the layer for the IPv6 header.
type IPv6 struct {
	// http://www.networksorcery.com/enp/protocol/ipv6.htm
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	Length       uint16
	NextHeader   IPProtocol
	HopLimit     uint8
	SrcIP        []byte
	DstIP        []byte
}

// LayerType returns LayerTypeIPv6
func (i *IPv6) LayerType() gopacket.LayerType { return LayerTypeIPv6 }
func (i *IPv6) NetworkFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointIP, i.SrcIP, i.DstIP)
}

func decodeIPv6(data []byte) (out gopacket.DecodeResult, err error) {
	ip6 := &IPv6{
		Version:      uint8(data[0]) >> 4,
		TrafficClass: uint8((binary.BigEndian.Uint16(data[0:2]) >> 4) & 0x00FF),
		FlowLabel:    binary.BigEndian.Uint32(data[0:4]) & 0x000FFFFF,
		Length:       binary.BigEndian.Uint16(data[4:6]),
		NextHeader:   IPProtocol(data[6]),
		HopLimit:     data[7],
		SrcIP:        data[8:24],
		DstIP:        data[24:40],
	}
	out.DecodedLayer = ip6
	out.RemainingBytes = data[40:]
	out.NextDecoder = ip6.NextHeader
	out.NetworkLayer = ip6
	return
}
