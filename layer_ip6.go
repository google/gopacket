// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
)

// IPv6 is the layer for the IPv6 header.
type IPv6 struct {
	// http://www.networksorcery.com/enp/protocol/ipv6.htm
	Version      uint8      // 4 bits
	TrafficClass uint8      // 8 bits
	FlowLabel    uint32     // 20 bits
	Length       uint16     // 16 bits
	NextHeader   IpProtocol // 8 bits, same as Protocol in Iphdr
	HopLimit     uint8      // 8 bits
	SrcIp        IPAddress  // 16 bytes
	DstIp        IPAddress  // 16 bytes
}

func (i *IPv6) LayerType() LayerType { return TYPE_IP6 }
func (i *IPv6) SrcNetAddr() Address  { return i.SrcIp }
func (i *IPv6) DstNetAddr() Address  { return i.DstIp }

var decodeIp6 decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	ip6 := &IPv6{
		Version:      uint8(data[0]) >> 4,
		TrafficClass: uint8((binary.BigEndian.Uint16(data[0:2]) >> 4) & 0x00FF),
		FlowLabel:    binary.BigEndian.Uint32(data[0:4]) & 0x000FFFFF,
		Length:       binary.BigEndian.Uint16(data[4:6]),
		NextHeader:   IpProtocol(data[6]),
		HopLimit:     data[7],
		SrcIp:        data[8:24],
		DstIp:        data[24:40],
	}
	out.layer = ip6
	out.left = data[40:]
	out.next = ip6.NextHeader
	s.network = ip6
	return
}
