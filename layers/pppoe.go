// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
	"encoding/binary"
)

// PPPoE is the layer for PPPoE encapsulation headers.
type PPPoE struct {
	baseLayer
	Version   uint8
	Type      uint8
	Code      PPPoECode
	SessionId uint16
	Length    uint16
}

// LayerType returns gopacket.LayerTypePPPoE.
func (p *PPPoE) LayerType() gopacket.LayerType {
	return LayerTypePPPoE
}

// decodePPPoE decodes the PPPoE header (see http://tools.ietf.org/html/rfc2516).
func decodePPPoE(data []byte, p gopacket.PacketBuilder) error {
	pppoe := &PPPoE{
		Version:   data[0] >> 4,
		Type:      data[0] & 0x0F,
		Code:      PPPoECode(data[1]),
		SessionId: binary.BigEndian.Uint16(data[2:4]),
		Length:    binary.BigEndian.Uint16(data[4:6]),
		baseLayer: baseLayer{data[:6], data[6:]},
	}
	p.AddLayer(pppoe)
	return p.NextDecoder(pppoe.Code)
}
