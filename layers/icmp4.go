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

type ICMPv4TypeCode uint16

const (
	ICMPv4TypeDestinationUnreachable = 3
	ICMPv4TypeTimeExceeded           = 11
	ICMPv4TypeParameterProblem       = 12
	ICMPv4TypeSourceQuench           = 4
	ICMPv4TypeRedirect               = 5
	ICMPv4TypeEchoRequest            = 8
	ICMPv4TypeEchoReply              = 0
	ICMPv4TypeTimestampRequest       = 13
	ICMPv4TypeTimestampReply         = 14
	ICMPv4TypeInfoRequest            = 15
	ICMPv4TypeInfoReply              = 16
)

// ICMPv4 is the layer for IPv4 ICMP packet data.
type ICMPv4 struct {
	BaseLayer
	TypeCode ICMPv4TypeCode
	Checksum uint16
	Id       uint16
	Seq      uint16
}

// LayerType returns gopacket.LayerTypeICMPv4
func (i *ICMPv4) LayerType() gopacket.LayerType { return LayerTypeICMPv4 }

func decodeICMPv4(data []byte, p gopacket.PacketBuilder) error {
	p.AddLayer(&ICMPv4{
		TypeCode:  ICMPv4TypeCode(binary.BigEndian.Uint16(data[:2])),
		Checksum:  binary.BigEndian.Uint16(data[2:4]),
		Id:        binary.BigEndian.Uint16(data[4:6]),
		Seq:       binary.BigEndian.Uint16(data[6:8]),
		BaseLayer: BaseLayer{data[:8], data[8:]},
	})
	return p.NextDecoder(gopacket.LayerTypePayload)
}

func (a ICMPv4TypeCode) String() string {
	typ := uint8(a >> 8)
	code := uint8(a)
	var typeStr, codeStr string
	switch typ {
	case ICMPv4TypeDestinationUnreachable:
		typeStr = "DestinationUnreachable"
		switch code {
		case 0:
			codeStr = "Net"
		case 1:
			codeStr = "Host"
		case 2:
			codeStr = "Protocol"
		case 3:
			codeStr = "Port"
		case 4:
			codeStr = "FragmentationNeeded"
		case 5:
			codeStr = "SourceRoutingFailed"
		}
	case ICMPv4TypeTimeExceeded:
		typeStr = "TimeExceeded"
		switch code {
		case 0:
			codeStr = "TTLExceeded"
		case 1:
			codeStr = "FragmentReassemblyTimeExceeded"
		}
	case ICMPv4TypeParameterProblem:
		typeStr = "ParameterProblem"
	case ICMPv4TypeSourceQuench:
		typeStr = "SourceQuench"
	case ICMPv4TypeRedirect:
		typeStr = "Redirect"
		switch code {
		case 0:
			codeStr = "Network"
		case 1:
			codeStr = "Host"
		case 2:
			codeStr = "TOS+Network"
		case 3:
			codeStr = "TOS+Host"
		}
	case ICMPv4TypeEchoRequest:
		typeStr = "EchoRequest"
	case ICMPv4TypeEchoReply:
		typeStr = "EchoReply"
	case ICMPv4TypeTimestampRequest:
		typeStr = "TimestampRequest"
	case ICMPv4TypeTimestampReply:
		typeStr = "TimestampReply"
	case ICMPv4TypeInfoRequest:
		typeStr = "InfoRequest"
	case ICMPv4TypeInfoReply:
		typeStr = "InfoReply"
	default:
		typeStr = strconv.Itoa(int(typ))
	}
	if codeStr == "" {
		codeStr = strconv.Itoa(int(code))
	}
	return fmt.Sprintf("%s(%s)", typeStr, codeStr)
}
