// Copyright 2012 Google, Inc. All rights reserved.

package layers

import (
	"encoding/binary"
	"github.com/gconnell/gopacket"
)

// IPSecAH is the authentication header for IPv4/6 defined in
// http://tools.ietf.org/html/rfc2402
type IPSecAH struct {
	// While the auth header can be used for both IPv4 and v6, its format is that of
	// an IPv6 extension (NextHeader, PayloadLength, etc...), so we use ipv6ExtensionBase
	// to build it.
	ipv6ExtensionBase
	Reserved           uint16
	SPI, Seq           uint32
	AuthenticationData []byte
}

// LayerType returns LayerTypeIPSecAH.
func (i *IPSecAH) LayerType() gopacket.LayerType { return LayerTypeIPSecAH }

func decodeIPSecAH(data []byte) (out gopacket.DecodeResult, err error) {
	i := &IPSecAH{
		ipv6ExtensionBase: decodeIPv6ExensionBase(data),
		Reserved:          binary.BigEndian.Uint16(data[2:4]),
		SPI:               binary.BigEndian.Uint32(data[4:8]),
		Seq:               binary.BigEndian.Uint32(data[8:12]),
	}
	i.AuthenticationData = i.contents[12:]
	out.DecodedLayer = i
	out.NextDecoder = i.NextHeader
	return
}

// IPSecESP is the encapsulating security payload defined in
// http://tools.ietf.org/html/rfc2406
type IPSecESP struct {
	baseLayer
	SPI, Seq uint32
	// Encrypted contains the encrypted set of bytes sent in an ESP
	Encrypted []byte
}

// LayerType returns LayerTypeIPSecESP.
func (i *IPSecESP) LayerType() gopacket.LayerType { return LayerTypeIPSecESP }

func decodeIPSecESP(data []byte) (out gopacket.DecodeResult, err error) {
	i := &IPSecESP{
		baseLayer: baseLayer{data, nil},
		SPI:       binary.BigEndian.Uint32(data[:4]),
		Seq:       binary.BigEndian.Uint32(data[4:8]),
		Encrypted: data[8:],
	}
	out.DecodedLayer = i
	return
}
