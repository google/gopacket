// Copyright (c) 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"encoding/binary"
)

// PPPoE is the layer for PPPoE encapsulation headers.
type PPPoE struct {
	Version   uint8
	Type      uint8
	Code      PPPoECode
	SessionId uint16
	Length    uint16
}

// LayerType returns LayerTypePPPoE.
func (p *PPPoE) LayerType() LayerType {
	return LayerTypePPPoE
}

// decodePPPoE decodes the PPPoE header (see http://tools.ietf.org/html/rfc2516).
func decodePPPoE(data []byte) (out DecodeResult, err error) {
	pppoe := &PPPoE{
		Version:   data[0] >> 4,
		Type:      data[0] & 0x0F,
		Code:      PPPoECode(data[1]),
		SessionId: binary.BigEndian.Uint16(data[2:4]),
		Length:    binary.BigEndian.Uint16(data[4:6]),
	}
	out.RemainingBytes = data[6:]
	out.DecodedLayer = pppoe
	out.NextDecoder = pppoe.Code
	return
}
