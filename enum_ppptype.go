// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"errors"
)

// PPPType is an enumeration of PPP type values, and acts as a decoder for any
// type it supports.
type PPPType uint16

const (
	PPPTypeIPv4 PPPType = 0x0021
	PPPTypeIPv6 PPPType = 0x0057
)

func (p PPPType) Decode(data []byte) (out DecodeResult, err error) {
	switch p {
	case PPPTypeIPv4:
		return decodeIp4(data)
	case PPPTypeIPv6:
		return decodeIp6(data)
	}
	err = errors.New("Unsupported PPP type")
	return
}
