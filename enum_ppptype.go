// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"fmt"
)

// PPPType is an enumeration of PPP type values, and acts as a decoder for any
// type it supports.
type PPPType uint16

const (
	PPPTypeIPv4 PPPType = 0x0021
	PPPTypeIPv6        PPPType =0x0057
)

func (p PPPType) Decode(data []byte) (out DecodeResult, err error) {
	switch p {
	case PPPTypeIPv4:
		return decodeIPv4(data)
	case PPPTypeIPv6:
		return decodeIPv6(data)
	}
	err = fmt.Errorf("Unsupported PPP type %d", p)
	return
}
