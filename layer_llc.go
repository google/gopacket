// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"encoding/binary"
)

// LLC is the layer used for 802.2 Logical Link Control headers.
// See http://standards.ieee.org/getieee802/download/802.2-1998.pdf
type LLC struct {
	DSAP    uint8
	IG      bool // true means group, false means individual
	SSAP    uint8
	CR      bool // true means response, false means command
	Control uint16
}

// LayerType returns LayerTypeLLC.
func (l *LLC) LayerType() LayerType { return LayerTypeLLC }

// SNAP is used inside LLC.  See
// http://standards.ieee.org/getieee802/download/802-2001.pdf.
// From http://en.wikipedia.org/wiki/Subnetwork_Access_Protocol:
//  "[T]he Subnetwork Access Protocol (SNAP) is a mechanism for multiplexing,
//  on networks using IEEE 802.2 LLC, more protocols than can be distinguished by
//  the 8-bit 802.2 Service Access Point (SAP) fields."
type SNAP struct {
	OrganizationalCode []byte
	Type               EthernetType
}

// LayerType returns LayerTypeSNAP.
func (s *SNAP) LayerType() LayerType { return LayerTypeSNAP }

func decodeLLC(data []byte) (out DecodeResult, err error) {
	l := &LLC{
		DSAP:    data[0] & 0xFE,
		IG:      data[0]&0x1 != 0,
		SSAP:    data[1] & 0xFE,
		CR:      data[1]&0x1 != 0,
		Control: uint16(data[2]),
	}
	if l.Control&0x1 == 0 || l.Control&0x3 == 0x1 {
		l.Control = l.Control<<8 | uint16(data[3])
		out.RemainingBytes = data[4:]
	} else {
		out.RemainingBytes = data[3:]
	}
	out.DecodedLayer = l
	if l.DSAP == 0xAA && l.SSAP == 0xAA {
		out.NextDecoder = decoderFunc(decodeSNAP)
	} else {
		out.NextDecoder = decoderFunc(decodeUnknown)
	}
	return
}

func decodeSNAP(data []byte) (out DecodeResult, err error) {
	s := &SNAP{
		OrganizationalCode: data[:3],
		Type:               EthernetType(binary.BigEndian.Uint16(data[3:5])),
	}
	out.DecodedLayer = s
	// BUG(gconnell):  This may not actually be an ethernet type in all cases,
	// depending on the organizational code.  Right now, we don't check.
	out.NextDecoder = s.Type
	out.RemainingBytes = data[5:]
	return
}
