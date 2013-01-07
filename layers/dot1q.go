// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
	"github.com/gconnell/gopacket"
)

// Dot1Q is the packet layer for 802.1Q VLAN headers.
type Dot1Q struct {
	baseLayer
	Priority       uint8
	DropEligible   bool
	VLANIdentifier uint16
	Type           EthernetType
}

// LayerType returns gopacket.LayerTypeDot1Q
func (d *Dot1Q) LayerType() gopacket.LayerType { return LayerTypeDot1Q }

func (v *Dot1Q) String() string {
	return fmt.Sprintf("VLAN Prioity:%d Drop:%v Tag:%d", v.Priority, v.DropEligible, v.VLANIdentifier)
}

func decodeDot1Q(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot1Q{
		Priority:       (data[2] & 0xE0) >> 13,
		DropEligible:   data[2]&0x10 != 0,
		VLANIdentifier: binary.BigEndian.Uint16(data[:2]) & 0x0FFF,
		Type:           EthernetType(binary.BigEndian.Uint16(data[2:4])),
		baseLayer:      baseLayer{contents: data[:4], payload: data[4:]},
	}
	p.AddLayer(d)
	return p.NextDecoder(d.Type)
}
