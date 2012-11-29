// Copyright (c) 2012 Google, Inc. All rights reserved.
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
	VLANIdentifier uint16
	Type           EthernetType
}

// Returns LayerTypeDot1Q
func (d *Dot1Q) LayerType() LayerType { return LayerTypeDot1Q }

func (v *Dot1Q) String() {
	fmt.Sprintf("VLAN Prioity:%d Drop:%v Tag:%d", v.Priority, v.DropEligible, v.VLANIdentifier)
}

var decodeDot1Q decoderFunc = func(data []byte) (out DecodeResult, err error) {
	d := &Dot1Q{
		Priority:       (data[2] & 0xE0) >> 13,
		DropEligible:   data[2]&0x10 != 0,
		VLANIdentifier: binary.BigEndian.Uint16(data[:2]) & 0x0FFF,
		Type:           EthernetType(binary.BigEndian.Uint16(data[2:4])),
	}
	out.DecodedLayer = d
	out.NextDecoder = d.Type
	out.RemainingBytes = data[4:]
	return
}
