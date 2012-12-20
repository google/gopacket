// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package layers

import (
	"encoding/binary"
	"fmt"
	"github.com/gconnell/gopacket"
	"net"
)

// IPv6 is the layer for the IPv6 header.
type IPv6 struct {
	// http://www.networksorcery.com/enp/protocol/ipv6.htm
	baseLayer
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
		baseLayer:    baseLayer{data[:40], data[40:]},
	}
	out.DecodedLayer = ip6
	out.NextDecoder = ip6.NextHeader
	out.NetworkLayer = ip6
	return
}

type ipv6HeaderTLVOption struct {
	OptionType, OptionLength uint8
	OptionData               []byte
}

func decodeIPv6HeaderTLVOption(data []byte) (h ipv6HeaderTLVOption) {
	if data[0] == 0 {
		h.OptionLength = 1
		return
	} else {
		h.OptionType = data[0]
		h.OptionLength = data[1]
		h.OptionData = data[2 : h.OptionLength+2]
	}
	return
}

// IPv6HopByHopOption is a TLV option present in an IPv6 hop-by-hop extension.
type IPv6HopByHopOption ipv6HeaderTLVOption

type ipv6ExtensionBase struct {
	baseLayer
	NextHeader   IPProtocol
	HeaderLength uint8
}

func (i ipv6ExtensionBase) ActualLength() int {
	return int(i.HeaderLength) * 8
}

func decodeIPv6ExensionBase(data []byte) (i ipv6ExtensionBase) {
	i.NextHeader = IPProtocol(data[0])
	i.HeaderLength = data[1]
	hlen := i.ActualLength()
	i.contents = data[:hlen]
	i.payload = data[hlen:]
	return
}

// IPv6HopByHop is the IPv6 hop-by-hop extension.
type IPv6HopByHop struct {
	ipv6ExtensionBase
	Options []IPv6HopByHopOption
}

// LayerType returns LayerTypeIPv6HopByHop.
func (i *IPv6HopByHop) LayerType() gopacket.LayerType { return LayerTypeIPv6HopByHop }

func decodeIPv6HopByHop(data []byte) (out gopacket.DecodeResult, err error) {
	i := &IPv6HopByHop{
		ipv6ExtensionBase: decodeIPv6ExensionBase(data),
		Options:           make([]IPv6HopByHopOption, 0, 2),
	}
	var opt *IPv6HopByHopOption
	for d := i.contents; len(d) > 0; d = d[:opt.OptionLength] {
		i.Options = append(i.Options, IPv6HopByHopOption(decodeIPv6HeaderTLVOption(d)))
		opt = &i.Options[len(i.Options)-1]
	}
	out.NextDecoder = i.NextHeader
	out.DecodedLayer = i
	return
}

// IPv6Routing is the IPv6 routing extension.
type IPv6Routing struct {
	ipv6ExtensionBase
	RoutingType  uint8
	SegmentsLeft uint8
	// This segment is supposed to be zero according to RFC2460, the second set of
	// 4 bytes in the extension.
	Reserved []byte
	// SourceRoutingIPs is the set of IPv6 addresses requested for source routing,
	// set only if RoutingType == 0.
	SourceRoutingIPs []net.IP
}

// LayerType returns LayerTypeIPv6Routing.
func (i *IPv6Routing) LayerType() gopacket.LayerType { return LayerTypeIPv6Routing }

func decodeIPv6Routing(data []byte) (out gopacket.DecodeResult, err error) {
	i := &IPv6Routing{
		ipv6ExtensionBase: decodeIPv6ExensionBase(data),
		RoutingType:       data[2],
		SegmentsLeft:      data[3],
		Reserved:          data[4:8],
	}
	switch i.RoutingType {
	case 0: // Source routing
		if (len(data)-8)%16 != 0 {
			err = fmt.Errorf("Invalid IPv6 source routing, length of type 0 packet %d", len(data))
		}
		for d := i.contents[8:]; len(d) >= 16; d = d[16:] {
			i.SourceRoutingIPs = append(i.SourceRoutingIPs, net.IP(d[:16]))
		}
	}
	out.DecodedLayer = i
	out.NextDecoder = i.NextHeader
	return
}
