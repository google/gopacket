// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
	"encoding/binary"
)

// Dot1Q is the packet layer for 802.1Q VLAN headers.
type Dot1Q struct {
	BaseLayer
	Priority       uint8
	DropEligible   bool
	VLANIdentifier uint16
	Type           EthernetType
}

// LayerType returns gopacket.LayerTypeDot1Q
func (d *Dot1Q) LayerType() gopacket.LayerType { return LayerTypeDot1Q }

func (d *Dot1Q) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	d.Priority = (data[2] & 0xE0) >> 13
	d.DropEligible = data[2]&0x10 != 0
	d.VLANIdentifier = binary.BigEndian.Uint16(data[:2]) & 0x0FFF
	d.Type = EthernetType(binary.BigEndian.Uint16(data[2:4]))
	d.BaseLayer = BaseLayer{Contents: data[:4], Payload: data[4:]}
	return nil
}

func (d *Dot1Q) CanDecode() gopacket.LayerClass {
	return LayerTypeDot1Q
}

func (d *Dot1Q) NextLayerType() gopacket.LayerType {
	return d.Type.LayerType()
}

func decodeDot1Q(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot1Q{}
	return decodingLayerDecoder(d, data, p)
}
