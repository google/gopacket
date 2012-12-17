// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
"github.com/gconnell/gopacket"
	"encoding/binary"
)

// GRE is a Generic Routing Encapsulation header.
type GRE struct {
	ChecksumPresent, RoutingPresent, KeyPresent, SeqPresent, StrictSourceRoute bool
	RecursionControl, Flags, Version                                           uint8
	Protocol                                                                   EthernetType
	Checksum, Offset                                                           uint16
	Key, Seq                                                                   uint32
	*GRERouting
}

// GRERouting is GRE routing information, present if the RoutingPresent flag is
// set.
type GRERouting struct {
	AddressFamily        uint16
	SREOffset, SRELength uint8
	RoutingInformation   []byte
}

// LayerType returns gopacket.LayerTypeGRE.
func (g *GRE) LayerType() gopacket.LayerType { return gopacket.LayerTypeGRE }

func decodeGRE(data []byte) (out gopacket.DecodeResult, err error) {
	g := &GRE{
		ChecksumPresent:   data[0]&0x80 != 0,
		RoutingPresent:    data[0]&0x40 != 0,
		KeyPresent:        data[0]&0x20 != 0,
		SeqPresent:        data[0]&0x10 != 0,
		StrictSourceRoute: data[0]&0x08 != 0,
		RecursionControl:  data[0] & 0x7,
		Flags:             data[1] >> 3,
		Version:           data[1] & 0x7,
		Protocol:          EthernetType(binary.BigEndian.Uint16(data[2:4])),
		Checksum:          binary.BigEndian.Uint16(data[4:6]),
		Offset:            binary.BigEndian.Uint16(data[6:8]),
		Key:               binary.BigEndian.Uint32(data[8:12]),
		Seq:               binary.BigEndian.Uint32(data[12:16]),
	}
	// reset data to point to after the main gre header
	data = data[16:]
	if g.RoutingPresent {
		g.GRERouting = &GRERouting{
			AddressFamily: binary.BigEndian.Uint16(data[:2]),
			SREOffset:     data[2],
			SRELength:     data[3],
		}
		end := g.SRELength + 4
		g.RoutingInformation = data[4:end]
		data = data[end:]
	}
	out.DecodedLayer = g
	out.NextDecoder = g.Protocol
	out.RemainingBytes = data
	return
}
