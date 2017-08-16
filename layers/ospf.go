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

// OSPFType denotes what kind of OSPF type it is
type OSPFType uint8

// Potential values for OSPF.Type.
const (
	OSPFHello                   OSPFType = 1
	OSPFDatabaseDescription     OSPFType = 2
	OSPFLinkStateRequest        OSPFType = 3
	OSPFLinkStateUpdate         OSPFType = 4
	OSPFLinkStateAcknowledgment OSPFType = 5
)

// String conversions for OSPFType
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

// OSPF is a basic OSPF packet header with common fields of Version 2 and Version 3.
type OSPF struct {
	Version      uint8
	Type         OSPFType
	PacketLength uint16
	RouterID     uint32
	AreaID       uint32
	Checksum     uint16
}

//OSPFv2 extend the OSPF head with version 2 specific fields
type OSPFv2 struct {
	BaseLayer
	OSPF
	AuType         uint16
	Authentication uint64
}

// OSPFv3 extend the OSPF head with version 3 specific fields
type OSPFv3 struct {
	BaseLayer
	OSPF
	Instance uint8
	Reserved uint8
}

// DecodeFromBytes decodes the given bytes into the OSPF layer.
func (ospf *OSPFv2) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 24 {
		return fmt.Errorf("Packet too smal for OSPF Version 2")
	}

	ospf.Version = uint8(data[0])
	ospf.Type = OSPFType(data[1])
	ospf.PacketLength = binary.BigEndian.Uint16(data[2:4])
	ospf.RouterID = binary.BigEndian.Uint32(data[4:8])
	ospf.AreaID = binary.BigEndian.Uint32(data[8:12])
	ospf.Checksum = binary.BigEndian.Uint16(data[12:14])
	ospf.AuType = binary.BigEndian.Uint16(data[14:16])
	ospf.Authentication = binary.BigEndian.Uint64(data[16:24])

	return nil
}

// DecodeFromBytes decodes the given bytes into the OSPF layer.
func (ospf *OSPFv3) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	if len(data) < 16 {
		return fmt.Errorf("Packet too smal for OSPF Version 3")
	}

	ospf.Version = uint8(data[0])
	ospf.Type = OSPFType(data[1])
	ospf.PacketLength = binary.BigEndian.Uint16(data[2:4])
	ospf.RouterID = binary.BigEndian.Uint32(data[4:8])
	ospf.AreaID = binary.BigEndian.Uint32(data[8:12])
	ospf.Checksum = binary.BigEndian.Uint16(data[12:14])
	ospf.Instance = uint8(data[14])
	ospf.Reserved = uint8(data[15])

	return nil
}

// LayerType returns LayerTypeOSPF
func (ospf *OSPFv2) LayerType() gopacket.LayerType {
	return LayerTypeOSPF
}
func (ospf *OSPFv3) LayerType() gopacket.LayerType {
	return LayerTypeOSPF
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (ospf *OSPFv2) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}
func (ospf *OSPFv3) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (ospf *OSPFv2) CanDecode() gopacket.LayerClass {
	return LayerTypeOSPF
}
func (ospf *OSPFv3) CanDecode() gopacket.LayerClass {
	return LayerTypeOSPF
}

func decodeOSPF(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 14 {
		return fmt.Errorf("Packet too smal for OSPF")
	}

	switch uint8(data[0]) {
	case 2:
		ospf := &OSPFv2{}
		return decodingLayerDecoder(ospf, data, p)
	case 3:
		ospf := &OSPFv3{}
		return decodingLayerDecoder(ospf, data, p)
	default:
	}

	return fmt.Errorf("Unable to determine OSPF type.")
}
