// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"errors"
)

// PppType is an enumeration of PPP type values, and acts as a decoder for any
// type it supports.
type PppType uint16

const (
	PPP_IP4 PppType = 0x0021
	PPP_IP6 PppType = 0x0057
)

func (p PppType) decode(data []byte, s *specificLayers) (out decodeResult) {
	switch p {
	case PPP_IP4:
		return decodeIp4(data, s)
	case PPP_IP6:
		return decodeIp6(data, s)
	}
	out.err = errors.New("Unsupported PPP type")
	return
}

func (p PppType) Decode(data []byte, lazy DecodeMethod) Packet {
	return newPacket(data, lazy, p)
}
