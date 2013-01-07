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

// ICMP is the layer for ICMP packet data.
type ICMP struct {
	baseLayer
	Type     uint8
	Code     uint8
	Checksum uint16
	Id       uint16
	Seq      uint16
}

// LayerType returns gopacket.LayerTypeICMP
func (i *ICMP) LayerType() gopacket.LayerType { return LayerTypeICMP }

func decodeICMP(data []byte, p gopacket.PacketBuilder) error {
	p.AddLayer(&ICMP{
		Type:      data[0],
		Code:      data[1],
		Checksum:  binary.BigEndian.Uint16(data[2:4]),
		Id:        binary.BigEndian.Uint16(data[4:6]),
		Seq:       binary.BigEndian.Uint16(data[6:8]),
		baseLayer: baseLayer{data[:8], data[8:]},
	})
	return p.NextDecoder(gopacket.LayerTypePayload)
}

func (icmp *ICMP) TypeString() (result string) {
	switch icmp.Type {
	case 0:
		result = fmt.Sprintf("Echo reply seq=%d", icmp.Seq)
	case 3:
		switch icmp.Code {
		case 0:
			result = "Network unreachable"
		case 1:
			result = "Host unreachable"
		case 2:
			result = "Protocol unreachable"
		case 3:
			result = "Port unreachable"
		default:
			result = "Destination unreachable"
		}
	case 8:
		result = fmt.Sprintf("Echo request seq=%d", icmp.Seq)
	case 30:
		result = "Traceroute"
	}
	return
}
