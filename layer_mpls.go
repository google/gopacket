// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"errors"
)

type MPLS struct {
	Label        uint32
	TrafficClass uint8
	StackBottom  bool
	TTL          uint8
}

// Returns LayerTypeMPLS
func (m *MPLS) LayerType() LayerType { return LayerTypeMPLS }

// ProtocolGuessingDecoder attempts to guess the protocol of the bytes it's
// given, then decode the packet accordingly.  Its algorithm for guessing is:
//  If packet starts with 3 bytes that are a valid ethernet prefix: Ethernet
//  If the packet starts with byte 0x4: IPv4
//  If the packet starts with byte 0x6: IPv6
type ProtocolGuessingDecoder struct{}

func (_ ProtocolGuessingDecoder) Decode(data []byte) (_ DecodeResult, err error) {
	ethPrefix := [3]byte{data[0], data[1], data[2]}
	if _, ok := MACPrefixToOrganization(ethPrefix); ok {
		return decodeEthernet(data)
	}
	switch data[0] {
	case 4:
		return decodeIp4(data)
	case 6:
		return decodeIp6(data)
	}
	err = errors.New("Unable to guess protocol of packet data")
	return
}

// MPLSPayloadDecoder is the decoder used to data encapsulated by each MPLS
// layer.  MPLS contains no type information, so we have to explicitly decide
// which decoder to use.  This is initially set to ProtocolGuessingDecoder, our
// simple attempt at guessing protocols based on the first few bytes of data
// available to us.  However, if you know that in your environment MPLS always
// encapsulates a specific protocol, you may reset this.
var MPLSPayloadDecoder Decoder = ProtocolGuessingDecoder{}

var decodeMpls decoderFunc = func(data []byte) (out DecodeResult, err error) {
	decoded := binary.BigEndian.Uint32(data[:4])
	out.DecodedLayer = &MPLS{
		Label:        decoded >> 12,
		TrafficClass: uint8(decoded>>9) & 0x7,
		StackBottom:  decoded&0x10 != 0,
		TTL:          uint8(decoded),
	}
	out.RemainingBytes = data[4:]
	out.NextDecoder = MPLSPayloadDecoder
	return
}
