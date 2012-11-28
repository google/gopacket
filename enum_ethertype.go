// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"errors"
)

type EthernetType uint16

const (
	ETHER_IP4   EthernetType = 0x0800
	ETHER_ARP   EthernetType = 0x0806
	ETHER_IP6   EthernetType = 0x86DD
	ETHER_DOT1Q EthernetType = 0x8100
)

func (e EthernetType) decode(data []byte, s *specificLayers) (out decodeResult) {
	switch e {
	case ETHER_IP4:
		return decodeIp4(data, s)
	case ETHER_IP6:
		return decodeIp6(data, s)
	case ETHER_ARP:
		return decodeArp(data, s)
	case ETHER_DOT1Q:
		return decodeDot1Q(data, s)
	}
	out.err = errors.New("Unsupported ethernet type")
	return
}

func (e EthernetType) Decode(data []byte, lazy DecodeMethod) Packet {
	return newPacket(data, lazy, e)
}
