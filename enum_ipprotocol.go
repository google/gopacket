// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"errors"
	"fmt"
)

// IPProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
type IPProtocol uint8

const (
	IPProtocolICMP IPProtocol = 1
	IPProtocolTCP  IPProtocol = 6
	IPProtocolUDP  IPProtocol = 17
)

func (ip IPProtocol) Decode(data []byte) (out DecodeResult, err error) {
	switch ip {
	case IPProtocolTCP:
		return decodeTcp(data)
	case IPProtocolUDP:
		return decodeUdp(data)
	case IPProtocolICMP:
		return decodeIcmp(data)
	}
	err = errors.New(fmt.Sprintf("Unsupported IP protocol %d", ip))
	return
}
