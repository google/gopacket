// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"errors"
)

type Ethernet struct {
	SrcMac, DstMac MacAddress
	EthernetType   EthernetType
}

func (e *Ethernet) LayerType() LayerType { return TYPE_ETHERNET }

func (e *Ethernet) SrcLinkAddr() Address {
	return e.SrcMac
}

func (e *Ethernet) DstLinkAddr() Address {
	return e.DstMac
}

// Decode decodes the headers of a Packet.
var decodeEthernet decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	if len(data) < 14 {
		out.err = errors.New("Ethernet packet too small")
		return
	}
	eth := &Ethernet{
		EthernetType: EthernetType(binary.BigEndian.Uint16(data[12:14])),
		DstMac:       MacAddress(data[0:6]),
		SrcMac:       MacAddress(data[6:12]),
	}
	out.layer = eth
	out.left = data[14:]
	out.next = eth.EthernetType
	s.link = eth
	return
}
