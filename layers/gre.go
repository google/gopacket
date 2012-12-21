// Copyright 2012 Google, Inc. All rights reserved.

package layers

import (
	"encoding/binary"
	"github.com/gconnell/gopacket"
)

// GRE is a Generic Routing Encapsulation header.
type GRE struct {
	baseLayer
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
func (g *GRE) LayerType() gopacket.LayerType { return LayerTypeGRE }

func decodeGRE(data []byte, p gopacket.PacketBuilder) error {
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
		baseLayer:         baseLayer{data[:16], data[16:]},
	}
	// reset data to point to after the main gre header
	rData := data[16:]
	if g.RoutingPresent {
		g.GRERouting = &GRERouting{
			AddressFamily: binary.BigEndian.Uint16(rData[:2]),
			SREOffset:     rData[2],
			SRELength:     rData[3],
		}
		end := g.SRELength + 4
		g.RoutingInformation = rData[4:end]
		g.contents = data[:16+end]
		g.payload = data[16+end:]
	}
	p.AddLayer(g)
	return p.NextDecoder(g.Protocol)
}
