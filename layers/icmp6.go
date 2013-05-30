// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
	"encoding/binary"
	"fmt"
	"strconv"
)

type ICMPv6TypeCode uint16

const (
	ICMPv6TypeDestinationUnreachable = 1
	ICMPv6TypePacketTooBig           = 2
	ICMPv6TypeTimeExceeded           = 3
	ICMPv6TypeParameterProblem       = 4
	ICMPv6TypeEchoRequest            = 128
	ICMPv6TypeEchoReply              = 129
	// The following are from RFC 4861
	ICMPv6TypeRouterSolicitation    = 133
	ICMPv6TypeRouterAdvertisement   = 134
	ICMPv6TypeNeighborSolicitation  = 135
	ICMPv6TypeNeighborAdvertisement = 136
	ICMPv6TypeRedirect              = 137
)

func (a ICMPv6TypeCode) String() string {
	typ := uint8(a >> 8)
	code := uint8(a)
	var typeStr, codeStr string
	switch typ {
	case ICMPv6TypeDestinationUnreachable:
		typeStr = "DestinationUnreachable"
		switch code {
		case 0:
			codeStr = "NoRouteToDst"
		case 1:
			codeStr = "AdminProhibited"
		case 3:
			codeStr = "Address"
		case 4:
			codeStr = "Port"
		}
	case ICMPv6TypePacketTooBig:
		typeStr = "PacketTooBig"
	case ICMPv6TypeTimeExceeded:
		typeStr = "TimeExceeded"
		switch code {
		case 0:
			codeStr = "HopLimitExceeded"
		case 1:
			codeStr = "FragmentReassemblyTimeExceeded"
		}
	case ICMPv6TypeParameterProblem:
		typeStr = "ParameterProblem"
		switch code {
		case 0:
			codeStr = "ErroneousHeader"
		case 1:
			codeStr = "UnrecognizedNextHeader"
		case 2:
			codeStr = "UnrecognizedIPv6Option"
		}
	case ICMPv6TypeEchoRequest:
		typeStr = "EchoRequest"
	case ICMPv6TypeEchoReply:
		typeStr = "EchoReply"
	case ICMPv6TypeRouterSolicitation:
		typeStr = "RouterSolicitation"
	case ICMPv6TypeRouterAdvertisement:
		typeStr = "RouterAdvertisement"
	case ICMPv6TypeNeighborSolicitation:
		typeStr = "NeighborSolicitation"
	case ICMPv6TypeNeighborAdvertisement:
		typeStr = "NeighborAdvertisement"
	case ICMPv6TypeRedirect:
		typeStr = "Redirect"
	default:
		typeStr = strconv.Itoa(int(typ))
	}
	if codeStr == "" {
		codeStr = strconv.Itoa(int(code))
	}
	return fmt.Sprintf("%s(%s)", typeStr, codeStr)
}

// ICMPv6 is the layer for IPv6 ICMP packet data
type ICMPv6 struct {
	BaseLayer
	TypeCode  ICMPv6TypeCode
	Checksum  uint16
	TypeBytes []byte
}

// LayerType returns LayerTypeICMPv6.
func (i *ICMPv6) LayerType() gopacket.LayerType { return LayerTypeICMPv6 }

func decodeICMPv6(data []byte, p gopacket.PacketBuilder) error {
	p.AddLayer(&ICMPv6{
		TypeCode:  ICMPv6TypeCode(binary.BigEndian.Uint16(data[:2])),
		Checksum:  binary.BigEndian.Uint16(data[2:4]),
		TypeBytes: data[4:8],
		BaseLayer: BaseLayer{data[:8], data[8:]},
	})
	return p.NextDecoder(gopacket.LayerTypePayload)
}
