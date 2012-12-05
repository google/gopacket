// Copyright (c) 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"fmt"
)

// PPPoECode is the PPPoE code enum, taken from http://tools.ietf.org/html/rfc2516
type PPPoECode int

const (
	PPPoECodePADI    PPPoECode = 0x09
	PPPoECodePADO    PPPoECode = 0x07
	PPPoECodePADR    PPPoECode = 0x19
	PPPoECodePADS    PPPoECode = 0x65
	PPPoECodePADT    PPPoECode = 0xA7
	PPPoECodeSession PPPoECode = 0x00
)

// Decode decodes a PPPoE payload, based on the PPPoECode.
func (p PPPoECode) Decode(data []byte) (_ DecodeResult, err error) {
	switch p {
	case PPPoECodeSession:
		return decodePPP(data)
	}
	err = fmt.Errorf("Cannot currently handle PPPoE error code %d", p)
	return
}
