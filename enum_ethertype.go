// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"fmt"
)

// EthernetType is an enumeration of ethernet type values, and acts as a decoder
// for any type it supports.
type EthernetType uint16

const (
	EthernetTypeIPv4  EthernetType = 0x0800
	EthernetTypeARP               EthernetType= 0x0806
	EthernetTypeIPv6              EthernetType= 0x86DD
	EthernetTypeDot1Q             EthernetType= 0x8100
)

func (e EthernetType) Decode(data []byte) (out DecodeResult, err error) {
	switch e {
	case EthernetTypeIPv4:
		return decodeIPv4(data)
	case EthernetTypeIPv6:
		return decodeIPv6(data)
	case EthernetTypeARP:
		return decodeARP(data)
	case EthernetTypeDot1Q:
		return decodeDot1Q(data)
	}
	err = fmt.Errorf("Unsupported ethernet type %d", e)
	return
}
