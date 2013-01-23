// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
)

// EAPOL defines an EAP over LAN (802.1x) layer.
type EAPOL struct {
	baseLayer
	Version uint8
	Type    EAPOLType
}

// LayerType returns LayerTypeEAPOL.
func (e *EAPOL) LayerType() gopacket.LayerType { return LayerTypeEAPOL }

func decodeEAPOL(data []byte, p gopacket.PacketBuilder) error {
	e := &EAPOL{
		Version:   data[0],
		Type:      EAPOLType(data[1]),
		baseLayer: baseLayer{data[:2], data[2:]},
	}
	p.AddLayer(e)
	return p.NextDecoder(e.Type)
}
