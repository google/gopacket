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

//  VXLAN is specifed in RFC 7348 https://tools.ietf.org/html/rfc7348
//  G, D, A, Group Policy ID from https://tools.ietf.org/html/draft-smith-vxlan-group-policy-00
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  0             8               16              24              32
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |G|R|R|R|I|R|R|R|R|D|R|R|A|R|R|R|       Group Policy ID         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     24 bit VXLAN Network Identifier           |   Reserved    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// VXLAN is a VXLAN packet header
type VXLAN struct {
	BaseLayer
	ValidIDFlag      bool   // 'I' bit per RFC 7348
	VNI              uint32 // 'VXLAN Network Identifier' 24 bits per RFC 7348
	GBPExtension     bool   // 'G' bit per Group Policy https://tools.ietf.org/html/draft-smith-vxlan-group-policy-00
	GBPDontLearn     bool   // 'D' bit per Group Policy
	GBPApplied       bool   // 'A' bit per Group Policy
	GBPGroupPolicyID uint16 // 'Group Policy ID' 16 bits per Group Policy
}

// LayerType returns LayerTypeVXLAN
func (vx *VXLAN) LayerType() gopacket.LayerType { return LayerTypeVXLAN }

func decodeVXLAN(data []byte, p gopacket.PacketBuilder) error {
	vx := &VXLAN{}

	// 'I' bit per RFC7348
	if (data[0] & 0x08) > 0 {
		vx.ValidIDFlag = true
	}

	// VNI - VXLAN Network Identifier per RFC7348
	vx.VNI = binary.BigEndian.Uint32(append([]byte{0x0}, data[4:7]...)) //Uint32 wants 4 bytes in a slice

	// 'G' bit per the group policy draft
	if (data[0] & 0x80) > 0 {
		vx.GBPExtension = true
	}

	// 'D' bit - the egress VTEP MUST NOT learn the source address of the encapsulated frame.
	if (data[1] & 0x40) > 0 {
		vx.GBPDontLearn = true
	}

	// 'A' bit - indicates that the group policy has already been applied to this packet.
	if (data[1] & 0x80) > 0 {
		vx.GBPApplied = true
	}

	// Policy ID as per the group policy draft
	vx.GBPGroupPolicyID = binary.BigEndian.Uint16(data[2:4])

	vxlanLength := 8
	vx.Contents = data[:vxlanLength]
	vx.Payload = data[vxlanLength:]

	p.AddLayer(vx)
	return p.NextDecoder(LinkType(1))
}
