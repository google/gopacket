// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"errors"
)

// PPP is the layer for PPP encapsulation headers.
type PPP struct {
	PppType PppType
}

type pppAddress []byte

var singletonPppAddress = pppAddress{}

func (p pppAddress) String() string {
	return "point"
}
func (p pppAddress) Raw() []byte {
	return p
}

func (p *PPP) SrcLinkAddr() Address { return singletonPppAddress }
func (p *PPP) DstLinkAddr() Address { return singletonPppAddress }

// Returns TYPE_PPP
func (p *PPP) LayerType() LayerType { return TYPE_PPP }

var decodePpp decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	ppp := &PPP{}
	if data[0]&0x1 == 0 {
		if data[1]&0x1 == 0 {
			out.err = errors.New("PPP has invalid type")
			return
		}
		ppp.PppType = PppType(binary.BigEndian.Uint16(data[:2]))
		out.left = data[2:]
	} else {
		ppp.PppType = PppType(data[0])
		out.left = data[1:]
	}
	out.layer = ppp
	out.next = ppp.PppType
	s.link = ppp
	return
}
