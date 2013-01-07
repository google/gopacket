// Copyright 2012 Google, Inc. All rights reserved.

package layers

import (
	"github.com/gconnell/gopacket"
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
