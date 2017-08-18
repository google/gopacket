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

type LSAheader struct {
	LSAge       uint16
	LSType      uint16
	LinkStateID uint32
	AdvRouter   uint32
	LSSeqNumber uint32
	LSChecksum  uint16
	Length      uint16
}

type LSReq struct {
	LSType    uint16
	LSID      uint32
	AdvRouter uint32
}

type DbDescPkg struct {
	Options      uint32
	InterfaceMTU uint16
	Flags        uint16
	DDSeqNumber  uint32
	LSAinfo      []LSAheader
}

type HelloPkg struct {
	InterfaceID              uint32
	RtrPriority              uint8
	Options                  uint32
	HelloInterval            uint16
	RouterDeadInterval       uint16
	DesignatedRouterID       uint32
	BackupDesignatedRouterID uint32
	NeighborID               []uint32
}

type HelloPkgV2 struct {
	HelloPkg
	NetworkMask uint32
}

// OSPF is a basic OSPF packet header with common fields of Version 2 and Version 3.
type OSPF struct {
	Version      uint8
	Type         OSPFType
	PacketLength uint16
	RouterID     uint32
	AreaID       uint32
	Checksum     uint16
	Content      interface{}
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

	switch ospf.Type {
	case OSPFHello:
		var neighbors []uint32
		for i := 36; uint16(i+4) <= ospf.PacketLength; i += 4 {
			neighbors = append(neighbors, binary.BigEndian.Uint32(data[i:i+4]))
		}
		ospf.Content = HelloPkg{
			InterfaceID:              binary.BigEndian.Uint32(data[16:20]),
			RtrPriority:              uint8(data[20]),
			Options:                  binary.BigEndian.Uint32(data[21:25]) >> 8,
			HelloInterval:            binary.BigEndian.Uint16(data[24:26]),
			RouterDeadInterval:       binary.BigEndian.Uint16(data[26:28]),
			DesignatedRouterID:       binary.BigEndian.Uint32(data[28:32]),
			BackupDesignatedRouterID: binary.BigEndian.Uint32(data[32:36]),
			NeighborID:               neighbors,
		}
	case OSPFDatabaseDescription:
		var lsas []LSAheader
		for i := 28; uint16(i+20) <= ospf.PacketLength; i += 20 {
			lsa := LSAheader{
				LSAge:       binary.BigEndian.Uint16(data[i : i+2]),
				LSType:      binary.BigEndian.Uint16(data[i+2 : i+4]),
				LinkStateID: binary.BigEndian.Uint32(data[i+4 : i+8]),
				AdvRouter:   binary.BigEndian.Uint32(data[i+8 : i+12]),
				LSSeqNumber: binary.BigEndian.Uint32(data[i+12 : i+16]),
				LSChecksum:  binary.BigEndian.Uint16(data[i+16 : i+18]),
				Length:      binary.BigEndian.Uint16(data[i+18 : i+20]),
			}
			lsas = append(lsas, lsa)
		}
		ospf.Content = DbDescPkg{
			Options:      binary.BigEndian.Uint32(data[16:20]) & 0x00FFFFFF,
			InterfaceMTU: binary.BigEndian.Uint16(data[20:22]),
			Flags:        binary.BigEndian.Uint16(data[22:24]),
			DDSeqNumber:  binary.BigEndian.Uint32(data[24:28]),
			LSAinfo:      lsas,
		}
	case OSPFLinkStateRequest:
		var lsrs []LSReq
		for i := 16; uint16(i+12) <= ospf.PacketLength; i += 12 {
			lsr := LSReq{
				LSType:    binary.BigEndian.Uint16(data[i+2 : i+4]),
				LSID:      binary.BigEndian.Uint32(data[i+4 : i+8]),
				AdvRouter: binary.BigEndian.Uint32(data[i+8 : i+12]),
			}
			lsrs = append(lsrs, lsr)
		}
		ospf.Content = lsrs
	case OSPFLinkStateAcknowledgment:
		var lsas []LSAheader
		for i := 16; uint16(i+20) <= ospf.PacketLength; i += 20 {
			lsa := LSAheader{
				LSAge:       binary.BigEndian.Uint16(data[i : i+2]),
				LSType:      binary.BigEndian.Uint16(data[i+2 : i+4]),
				LinkStateID: binary.BigEndian.Uint32(data[i+4 : i+8]),
				AdvRouter:   binary.BigEndian.Uint32(data[i+8 : i+12]),
				LSSeqNumber: binary.BigEndian.Uint32(data[i+12 : i+16]),
				LSChecksum:  binary.BigEndian.Uint16(data[i+16 : i+18]),
				Length:      binary.BigEndian.Uint16(data[i+18 : i+20]),
			}
			lsas = append(lsas, lsa)
		}
		ospf.Content = lsas
	default:
	}

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
