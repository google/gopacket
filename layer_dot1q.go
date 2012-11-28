// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"fmt"
)

// Dot1Q is the packet layer for 802.1Q VLAN headers.
type Dot1Q struct {
	Priority       uint8
	DropEligible   bool
	VlanIdentifier uint16
	Type           IpProtocol
}

func (d *Dot1Q) LayerType() LayerType { return TYPE_DOT1Q }

func (v *Dot1Q) String() {
	fmt.Sprintf("VLAN Prioity:%d Drop:%v Tag:%d", v.Priority, v.DropEligible, v.VlanIdentifier)
}

var decodeDot1Q decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	d := &Dot1Q{
		Priority:       (data[2] & 0xE0) >> 13,
		DropEligible:   data[2]&0x10 != 0,
		VlanIdentifier: binary.BigEndian.Uint16(data[:2]) & 0x0FFF,
		Type:           IpProtocol(binary.BigEndian.Uint16(data[2:4])),
	}
	out.layer = d
	out.next = d.Type
	out.left = data[4:]
	return
}
