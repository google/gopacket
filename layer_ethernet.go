// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"errors"
)

// Ethernet is the layer for Ethernet frame headers.
type Ethernet struct {
	SrcMAC, DstMAC MACAddress
	EthernetType   EthernetType
}

// Returns TYPE_ETHERNET
func (e *Ethernet) LayerType() LayerType { return TYPE_ETHERNET }

func (e *Ethernet) SrcLinkAddr() Address {
	return e.SrcMAC
}

func (e *Ethernet) DstLinkAddr() Address {
	return e.DstMAC
}

// Decode decodes the headers of a Packet.
var decodeEthernet decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	if len(data) < 14 {
		out.err = errors.New("Ethernet packet too small")
		return
	}
	eth := &Ethernet{
		EthernetType: EthernetType(binary.BigEndian.Uint16(data[12:14])),
		DstMAC:       MACAddress(data[0:6]),
		SrcMAC:       MACAddress(data[6:12]),
	}
	out.layer = eth
	out.left = data[14:]
	out.next = eth.EthernetType
	s.link = eth
	return
}
