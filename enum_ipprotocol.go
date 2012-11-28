// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"errors"
)

// IpProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
type IpProtocol uint8

const (
	IP_ICMP IpProtocol = 1
	IP_TCP  IpProtocol = 6
	IP_UDP  IpProtocol = 17
)

func (ip IpProtocol) decode(data []byte, s *specificLayers) (out decodeResult) {
	switch ip {
	case IP_TCP:
		return decodeTcp(data, s)
	case IP_UDP:
		return decodeUdp(data, s)
	case IP_ICMP:
		return decodeIcmp(data, s)
	}
	out.err = errors.New("Unsupported IP protocol")
	return
}

func (ip IpProtocol) Decode(data []byte, lazy DecodeMethod) Packet {
	return newPacket(data, lazy, ip)
}
