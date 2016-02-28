// Copyright 2016 Robert Clark. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"github.com/google/gopacket"
)

// VXLAN is specifed in RFC 7348
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  0             8               16              24              32
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |R|R|R|R|I|R|R|R|           24 bit Reserved                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     24 bit VXLAN Network Identifier           |   Reserved    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// VXLAN is a VXLAN packet header
type VXLAN struct {
	BaseLayer
	ValidIDFlag      bool   // The 'I' flag from https://tools.ietf.org/html/rfc7348#page-10
	VNI              uint32 //24 bits / 3 bytes
	GBPExtension     bool   //https://tools.ietf.org/html/draft-smith-vxlan-group-policy-00
	GBPDontLearn     bool
	GBPApplied       bool //Funnily enough, this means the policy has already been applied
	GBPGroupPolicyID uint16
}

// LayerType returns LayerTypeVXLAN
func (vx *VXLAN) LayerType() gopacket.LayerType { return LayerTypeVXLAN }

func decodeVXLAN(data []byte, p gopacket.PacketBuilder) error {
	vx := &VXLAN{}

	//Bits 0-3 and 5-7 are reserved and should be ignored by receivers however GBP is also a thing
	if (data[0] & 0x08) > 0 {
		vx.ValidIDFlag = true
	}
	vx.VNI = binary.BigEndian.Uint32(append([]byte{0x0}, data[4:7]...)) //Uint32 wants 4 bytes in a slice

	//'G' bit per the group policy RFC draft
	if (data[0] & 0x80) > 0 {
		vx.GBPExtension = true
	}

	//'D' bit - the egress VTEP MUST NOT learn the source address of the encapsulated frame.
	if (data[1] & 0x40) > 0 {
		vx.GBPDontLearn = true
	}

	//'A' bit - indicates that the group policy has already been applied to this packet.
	if (data[1] & 0x80) > 0 {
		vx.GBPApplied = true
	}

	vx.GBPGroupPolicyID = binary.BigEndian.Uint16(data[2:4])

	vxlanLength := 8
	vx.Contents = data[:vxlanLength]
	vx.Payload = data[vxlanLength:]
	p.AddLayer(vx)
	return p.NextDecoder(LinkType(1))
}
