// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"errors"
)

// EthernetType is an enumeration of ethernet type values, and acts as a decoder
// for any type it supports.
type EthernetType uint16

const (
	EthernetTypeIPv4  EthernetType = 0x0800
	EthernetTypeARP   EthernetType = 0x0806
	EthernetTypeIPv6  EthernetType = 0x86DD
	EthernetTypeDot1Q EthernetType = 0x8100
)

func (e EthernetType) Decode(data []byte) (out DecodeResult, err error) {
	switch e {
	case EthernetTypeIPv4:
		return decodeIp4(data)
	case EthernetTypeIPv6:
		return decodeIp6(data)
	case EthernetTypeARP:
		return decodeArp(data)
	case EthernetTypeDot1Q:
		return decodeDot1Q(data)
	}
	err = errors.New("Unsupported ethernet type")
	return
}
