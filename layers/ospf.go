// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

type OSPFType uint8

// Potential values for OSPF.Type.
const (
	OSPFHello                   OSPFType = 1
	OSPFDatabaseDescription     OSPFType = 2
	OSPFLinkStateRequest        OSPFType = 3
	OSPFLinkStateUpdate         OSPFType = 4
	OSPFLinkStateAcknowledgment OSPFType = 5
)

func (i OSPFType) String() string {
	switch i {
	case OSPFHello:
		return "Hello"
	case OSPFDatabaseDescription:
		return "Database Description"
	case OSPFLinkStateRequest:
		return "Link State Request"
	case OSPFLinkStateUpdate:
		return "Link State Update"
	case OSPFLinkStateAcknowledgment:
		return "Link State Acknowledgment"
	default:
		return ""
	}
}

//OSPFv2 extend the OSPF head with version 2 specific fields
type OSPFv2 struct {
	AuType         uint16
	Authentication uint64
}

// OSPFv3 extend the OSPF head with version 3 specific fields
type OSPFv3 struct {
	Instance uint8
	Reserved uint8
}

// OSPF is a basic OSPF packet header with common fields of Version 2 and Version 3.
type OSPF struct {
	BaseLayer
	OSPFv2
	OSPFv3
	Version      uint8
	Type         OSPFType
	PacketLength uint16
	RouterID     uint32
	AreaID       uint32
	Checksum     uint16
}

func (ospf *OSPF) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 14 {
		return fmt.Errorf("Packet too smal for OSPF")
	}

	ospf.Version = uint8(data[0])
	ospf.Type = OSPFType(data[1])
	ospf.PacketLength = binary.BigEndian.Uint16(data[2:4])
	ospf.RouterID = binary.BigEndian.Uint32(data[4:8])
	ospf.AreaID = binary.BigEndian.Uint32(data[8:12])
	ospf.Checksum = binary.BigEndian.Uint16(data[12:14])

	switch ospf.Version {
	case 2:
		if len(data) < 24 {
			return fmt.Errorf("Packet too smal for OSPF Version 2")
		}
		ospf.AuType = binary.BigEndian.Uint16(data[14:16])
		ospf.Authentication = binary.BigEndian.Uint64(data[16:24])
	case 3:
		if len(data) < 16 {
			return fmt.Errorf("Packet too smal for OSPF Version 3")
		}
		ospf.Instance = uint8(data[14])
		ospf.Reserved = uint8(data[15])
	default:
		return fmt.Errorf("Unsupported OSPF version")
	}

	return nil
}

// LayerType returns LayerTypeOSPF
func (ospf *OSPF) LayerType() gopacket.LayerType {
	return LayerTypeOSPF
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (ospf *OSPF) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (ospf *OSPF) CanDecode() gopacket.LayerClass {
	return LayerTypeOSPF
}

func decodeOSPF(data []byte, p gopacket.PacketBuilder) error {

	ospf := &OSPF{}
	return decodingLayerDecoder(ospf, data, p)
}
