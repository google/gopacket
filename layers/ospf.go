// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
	"reflect"

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

// LSA Function Codes for LSAheader.LSType
const (
	RouterLSAtypeV2         = 0x1
	RouterLSAtype           = 0x2001
	NetworkLSAtypeV2        = 0x2
	NetworkLSAtype          = 0x2002
	SummaryLSANetworktypeV2 = 0x3
	InterAreaPrefixLSAtype  = 0x2003
	SummaryLSAASBRtypeV2    = 0x4
	InterAreaRouterLSAtype  = 0x2004
	ASExternalLSAtypeV2     = 0x5
	ASExternalLSAtype       = 0x4005
	NSSALSAtype             = 0x2007
	NSSALSAtypeV2           = 0x7
	LinkLSAtype             = 0x0008
	IntraAreaPrefixLSAtype  = 0x2009
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

// Prefix extends IntraAreaPrefixLSA
type Prefix struct {
	PrefixLength  uint8
	PrefixOptions uint8
	Metric        uint16
	AddressPrefix []byte
}

// IntraAreaPrefixLSA is the struct from RFC 5340  A.4.10.
type IntraAreaPrefixLSA struct {
	NumOfPrefixes  uint16
	RefLSType      uint16
	RefLinkStateID uint32
	RefAdvRouter   uint32
	Prefixes       []Prefix
}

// LinkLSA is the struct from RFC 5340  A.4.9.
type LinkLSA struct {
	RtrPriority      uint8
	Options          uint32
	LinkLocalAddress []byte
	NumOfPrefixes    uint32
	Prefixes         []Prefix
}

// ASExternalLSAV2 is the struct from RFC 2328  A.4.5.
type ASExternalLSAV2 struct {
	NetworkMask       uint32
	ExternalBit       uint8
	Metric            uint32
	ForwardingAddress uint32
	ExternalRouteTag  uint32
}

// ASExternalLSA is the struct from RFC 5340  A.4.7.
type ASExternalLSA struct {
	Flags             uint8
	Metric            uint32
	PrefixLength      uint8
	PrefixOptions     uint8
	RefLSType         uint16
	AddressPrefix     []byte
	ForwardingAddress []byte
	ExternalRouteTag  uint32
	RefLinkStateID    uint32
}

// InterAreaRouterLSA is the struct from RFC 5340  A.4.6.
type InterAreaRouterLSA struct {
	Options             uint32
	Metric              uint32
	DestinationRouterID uint32
}

// InterAreaPrefixLSA is the struct from RFC 5340  A.4.5.
type InterAreaPrefixLSA struct {
	Metric        uint32
	PrefixLength  uint8
	PrefixOptions uint8
	AddressPrefix []byte
}

// NetworkLSA is the struct from RFC 5340  A.4.4.
type NetworkLSA struct {
	Options        uint32
	AttachedRouter []uint32
}

// NetworkLSAV2 is the struct from RFC 2328  A.4.3.
type NetworkLSAV2 struct {
	NetworkMask    uint32
	AttachedRouter []uint32
}

// RouterV2 extends RouterLSAV2
type RouterV2 struct {
	Type     uint8
	LinkID   uint32
	LinkData uint32
	Metric   uint16
}

// RouterLSAV2 is the struct from RFC 2328  A.4.2.
type RouterLSAV2 struct {
	Flags   uint8
	Links   uint16
	Routers []RouterV2
}

// Router extends RouterLSA
type Router struct {
	Type                uint8
	Metric              uint16
	InterfaceID         uint32
	NeighborInterfaceID uint32
	NeighborRouterID    uint32
}

// RouterLSA is the struct from RFC 5340  A.4.3.
type RouterLSA struct {
	Flags   uint8
	Options uint32
	Routers []Router
}

// LSAheader is the struct from RFC 5340  A.4.2 and RFC 2328 A.4.1.
type LSAheader struct {
	LSAge       uint16
	LSType      uint16
	LinkStateID uint32
	AdvRouter   uint32
	LSSeqNumber uint32
	LSChecksum  uint16
	Length      uint16
	LSOptions   uint8
}

// LSA links LSAheader with the structs from RFC 5340  A.4.
type LSA struct {
	LSAheader
	Content interface{}
}

// LSUpdate is the struct from RFC 5340  A.3.5.
type LSUpdate struct {
	NumOfLSAs uint32
	LSAs      []LSA
}

// LSReq is the struct from RFC 5340  A.3.4.
type LSReq struct {
	LSType    uint16
	LSID      uint32
	AdvRouter uint32
}

// DbDescPkg is the struct from RFC 5340  A.3.3.
type DbDescPkg struct {
	Options      uint32
	InterfaceMTU uint16
	Flags        uint16
	DDSeqNumber  uint32
	LSAinfo      []LSAheader
}

// HelloPkg  is the struct from RFC 5340  A.3.2.
type HelloPkg struct {
	InterfaceID              uint32
	RtrPriority              uint8
	Options                  uint32
	HelloInterval            uint16
	RouterDeadInterval       uint32
	DesignatedRouterID       uint32
	BackupDesignatedRouterID uint32
	NeighborID               []uint32
}

// HelloPkgV2 extends the HelloPkg struct with OSPFv2 information
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
	tcpipchecksum
}

// getLSAsv2 parses the LSA information from the packet for OSPFv2
func getLSAsv2(num uint32, data []byte) ([]LSA, error) {
	var lsas []LSA
	var i uint32 = 0
	var offset uint32 = 0
	for ; i < num; i++ {
		lstype := uint16(data[offset+3])
		lsalength := binary.BigEndian.Uint16(data[offset+18 : offset+20])
		content, err := extractLSAInformation(lstype, lsalength, data[offset:])
		if err != nil {
			return nil, fmt.Errorf("Could not extract Link State type.")
		}
		lsa := LSA{
			LSAheader: LSAheader{
				LSAge:       binary.BigEndian.Uint16(data[offset : offset+2]),
				LSOptions:   data[offset+2],
				LSType:      lstype,
				LinkStateID: binary.BigEndian.Uint32(data[offset+4 : offset+8]),
				AdvRouter:   binary.BigEndian.Uint32(data[offset+8 : offset+12]),
				LSSeqNumber: binary.BigEndian.Uint32(data[offset+12 : offset+16]),
				LSChecksum:  binary.BigEndian.Uint16(data[offset+16 : offset+18]),
				Length:      lsalength,
			},
			Content: content,
		}
		lsas = append(lsas, lsa)
		offset += uint32(lsalength)
	}
	return lsas, nil
}

// extractLSAInformation extracts all the LSA information
func extractLSAInformation(lstype, lsalength uint16, data []byte) (interface{}, error) {
	if lsalength < 20 {
		return nil, fmt.Errorf("Link State header length %v too short, %v required", lsalength, 20)
	}
	if len(data) < int(lsalength) {
		return nil, fmt.Errorf("Link State header length %v too short, %v required", len(data), lsalength)
	}
	var content interface{}
	switch lstype {
	case RouterLSAtypeV2:
		var routers []RouterV2
		var j uint32
		for j = 24; j < uint32(lsalength); j += 12 {
			router := RouterV2{
				LinkID:   binary.BigEndian.Uint32(data[j : j+4]),
				LinkData: binary.BigEndian.Uint32(data[j+4 : j+8]),
				Type:     uint8(data[j+8]),
				Metric:   binary.BigEndian.Uint16(data[j+10 : j+12]),
			}
			routers = append(routers, router)
		}
		links := binary.BigEndian.Uint16(data[22:24])
		content = RouterLSAV2{
			Flags:   data[20],
			Links:   links,
			Routers: routers,
		}
	case NSSALSAtypeV2:
		fallthrough
	case ASExternalLSAtypeV2:
		content = ASExternalLSAV2{
			NetworkMask:       binary.BigEndian.Uint32(data[20:24]),
			ExternalBit:       data[24] & 0x80,
			Metric:            binary.BigEndian.Uint32(data[24:28]) & 0x00FFFFFF,
			ForwardingAddress: binary.BigEndian.Uint32(data[28:32]),
			ExternalRouteTag:  binary.BigEndian.Uint32(data[32:36]),
		}
	case NetworkLSAtypeV2:
		var routers []uint32
		var j uint32
		for j = 24; j < uint32(lsalength); j += 4 {
			routers = append(routers, binary.BigEndian.Uint32(data[j:j+4]))
		}
		content = NetworkLSAV2{
			NetworkMask:    binary.BigEndian.Uint32(data[20:24]),
			AttachedRouter: routers,
		}
	case RouterLSAtype:
		var routers []Router
		var j uint32
		for j = 24; j < uint32(lsalength); j += 16 {
			router := Router{
				Type:                uint8(data[j]),
				Metric:              binary.BigEndian.Uint16(data[j+2 : j+4]),
				InterfaceID:         binary.BigEndian.Uint32(data[j+4 : j+8]),
				NeighborInterfaceID: binary.BigEndian.Uint32(data[j+8 : j+12]),
				NeighborRouterID:    binary.BigEndian.Uint32(data[j+12 : j+16]),
			}
			routers = append(routers, router)
		}
		content = RouterLSA{
			Flags:   uint8(data[20]),
			Options: binary.BigEndian.Uint32(data[20:24]) & 0x00FFFFFF,
			Routers: routers,
		}
	case NetworkLSAtype:
		var routers []uint32
		var j uint32
		for j = 24; j < uint32(lsalength); j += 4 {
			routers = append(routers, binary.BigEndian.Uint32(data[j:j+4]))
		}
		content = NetworkLSA{
			Options:        binary.BigEndian.Uint32(data[20:24]) & 0x00FFFFFF,
			AttachedRouter: routers,
		}
	case InterAreaPrefixLSAtype:
		content = InterAreaPrefixLSA{
			Metric:        binary.BigEndian.Uint32(data[20:24]) & 0x00FFFFFF,
			PrefixLength:  uint8(data[24]),
			PrefixOptions: uint8(data[25]),
			AddressPrefix: data[28:uint32(lsalength)],
		}
	case InterAreaRouterLSAtype:
		content = InterAreaRouterLSA{
			Options:             binary.BigEndian.Uint32(data[20:24]) & 0x00FFFFFF,
			Metric:              binary.BigEndian.Uint32(data[24:28]) & 0x00FFFFFF,
			DestinationRouterID: binary.BigEndian.Uint32(data[28:32]),
		}
	case ASExternalLSAtype:
		fallthrough
	case NSSALSAtype:

		flags := uint8(data[20])
		prefixLen := uint8(data[24]) / 8
		var forwardingAddress []byte
		if (flags & 0x02) == 0x02 {
			forwardingAddress = data[28+uint32(prefixLen) : 28+uint32(prefixLen)+16]
		}
		content = ASExternalLSA{
			Flags:             flags,
			Metric:            binary.BigEndian.Uint32(data[20:24]) & 0x00FFFFFF,
			PrefixLength:      prefixLen,
			PrefixOptions:     uint8(data[25]),
			RefLSType:         binary.BigEndian.Uint16(data[26:28]),
			AddressPrefix:     data[28 : 28+uint32(prefixLen)],
			ForwardingAddress: forwardingAddress,
		}
	case LinkLSAtype:
		var prefixes []Prefix
		var prefixOffset uint32 = 44
		var j uint32
		numOfPrefixes := binary.BigEndian.Uint32(data[40:44])
		for j = 0; j < numOfPrefixes; j++ {
			prefixLen := uint8(data[prefixOffset])
			prefix := Prefix{
				PrefixLength:  prefixLen,
				PrefixOptions: uint8(data[prefixOffset+1]),
				AddressPrefix: data[prefixOffset+4 : prefixOffset+4+uint32(prefixLen)/8],
			}
			prefixes = append(prefixes, prefix)
			prefixOffset = prefixOffset + 4 + uint32(prefixLen)/8
		}
		content = LinkLSA{
			RtrPriority:      uint8(data[20]),
			Options:          binary.BigEndian.Uint32(data[20:24]) & 0x00FFFFFF,
			LinkLocalAddress: data[24:40],
			NumOfPrefixes:    numOfPrefixes,
			Prefixes:         prefixes,
		}
	case IntraAreaPrefixLSAtype:
		var prefixes []Prefix
		var prefixOffset uint32 = 32
		var j uint16
		numOfPrefixes := binary.BigEndian.Uint16(data[20:22])
		for j = 0; j < numOfPrefixes; j++ {
			prefixLen := uint8(data[prefixOffset])
			prefix := Prefix{
				PrefixLength:  prefixLen,
				PrefixOptions: uint8(data[prefixOffset+1]),
				Metric:        binary.BigEndian.Uint16(data[prefixOffset+2 : prefixOffset+4]),
				AddressPrefix: data[prefixOffset+4 : prefixOffset+4+uint32(prefixLen)/8],
			}
			prefixes = append(prefixes, prefix)
			prefixOffset = prefixOffset + 4 + uint32(prefixLen)
		}
		content = IntraAreaPrefixLSA{
			NumOfPrefixes:  numOfPrefixes,
			RefLSType:      binary.BigEndian.Uint16(data[22:24]),
			RefLinkStateID: binary.BigEndian.Uint32(data[24:28]),
			RefAdvRouter:   binary.BigEndian.Uint32(data[28:32]),
			Prefixes:       prefixes,
		}
	default:
		return nil, fmt.Errorf("Unknown Link State type.")
	}
	return content, nil
}

func getArchivedLSAInformationSize(lsa LSA) (int, error) {
	switch lsa.LSType {
	case RouterLSAtypeV2:
		if _, ok := lsa.Content.(RouterLSAV2); ok {
			// return 20 + 3 + len(content.Routers)*7, nil
			return 20, nil
		}
		return 0, fmt.Errorf("Invalid Content: want RouterLSAV2, got %s", reflect.TypeOf(lsa.Content))
	case NSSALSAtypeV2:
		fallthrough
	case ASExternalLSAtypeV2:
		if _, ok := lsa.Content.(ASExternalLSAV2); ok {
			// return 20 + 16, nil
			return 20, nil
		}
		return 0, fmt.Errorf("Invalid Content: want ASExternalLSAV2, got %s", reflect.TypeOf(lsa.Content))
	case NetworkLSAtypeV2:
		if _, ok := lsa.Content.(NetworkLSAV2); ok {
			// return 20 + 4 + len(content.AttachedRouter)*4, nil
			return 20, nil
		}
		return 0, fmt.Errorf("Invalid Content: want NetworkLSAV2, got %s", reflect.TypeOf(lsa.Content))
	case RouterLSAtype:
		if content, ok := lsa.Content.(RouterLSA); ok {
			return 20 + 4 + len(content.Routers)*16, nil
		}
		return 0, fmt.Errorf("Invalid Content: want RouterLSA, got %s", reflect.TypeOf(lsa.Content))
	case NetworkLSAtype:
		if _, ok := lsa.Content.(NetworkLSA); ok {
			// return 20 + 4 + len(content.AttachedRouter)*4, nil
			return 20, nil
		}
		return 0, fmt.Errorf("Invalid Content: want NetworkLSA, got %s", reflect.TypeOf(lsa.Content))
	case InterAreaPrefixLSAtype:
		if content, ok := lsa.Content.(InterAreaPrefixLSA); ok {
			return 20 + 8 + len(content.AddressPrefix), nil
		}
		return 0, fmt.Errorf("Invalid Content: want InterAreaPrefixLSA, got %s", reflect.TypeOf(lsa.Content))
	case InterAreaRouterLSAtype:
		if _, ok := lsa.Content.(InterAreaRouterLSA); ok {
			// return 20 + 12, nil
			return 20, nil
		}
		return 0, fmt.Errorf("Invalid Content: want InterAreaRouterLSA, got %s", reflect.TypeOf(lsa.Content))
	case ASExternalLSAtype:
		fallthrough
	case NSSALSAtype:
		if _, ok := lsa.Content.(ASExternalLSA); ok {
			// return 20 + 8 + len(content.AddressPrefix) + 16, nil
			return 20, nil
		}
		return 0, fmt.Errorf("Invalid Content: want ASExternalLSA, got %s", reflect.TypeOf(lsa.Content))
	case LinkLSAtype:
		if content, ok := lsa.Content.(LinkLSA); ok {
			size := 20 + 24
			for _, prefix := range content.Prefixes {
				size += 4 + int(prefix.PrefixLength)/8
			}
			return size, nil
		}
		return 0, fmt.Errorf("Invalid Content: want LinkLSA, got %s", reflect.TypeOf(lsa.Content))
	case IntraAreaPrefixLSAtype:
		if content, ok := lsa.Content.(IntraAreaPrefixLSA); ok {
			size := 20 + 12
			for _, prefix := range content.Prefixes {
				size += 4 + int(prefix.PrefixLength)/8
			}
			return size, nil
		}
		return 0, fmt.Errorf("Invalid Content: want IntraAreaPrefixLSA, got %s", reflect.TypeOf(lsa.Content))
	default:
		return 0, fmt.Errorf("Unknown LSA Type")
	}
}

func archiveLSAInformation(lstype uint16, lsa LSA, lsalength int, data []byte, offset int) error {
	binary.BigEndian.PutUint16(data[offset:offset+2], lsa.LSAge)
	binary.BigEndian.PutUint16(data[offset+2:offset+4], lsa.LSType)
	binary.BigEndian.PutUint32(data[offset+4:offset+8], lsa.LinkStateID)
	binary.BigEndian.PutUint32(data[offset+8:offset+12], lsa.AdvRouter)
	binary.BigEndian.PutUint32(data[offset+12:offset+16], lsa.LSSeqNumber)
	binary.BigEndian.PutUint16(data[offset+16:offset+18], lsa.LSChecksum)
	binary.BigEndian.PutUint16(data[offset+18:offset+20], lsa.Length)
	offset += 20
	switch lstype {
	case RouterLSAtypeV2:
		if _, ok := lsa.Content.(RouterLSAV2); ok {
			return nil
		}
		return fmt.Errorf("Invalid Content: want RouterLSAV2, got %s", reflect.TypeOf(lsa))
	case NSSALSAtypeV2:
		fallthrough
	case ASExternalLSAtypeV2:
		if _, ok := lsa.Content.(ASExternalLSAV2); ok {
			return nil
		}
		return fmt.Errorf("Invalid Content: want ASExternalLSAV2, got %s", reflect.TypeOf(lsa))
	case NetworkLSAtypeV2:
		if _, ok := lsa.Content.(NetworkLSAV2); ok {
			return nil
		}
		return fmt.Errorf("Invalid Content: want NetworkLSAV2, got %s", reflect.TypeOf(lsa))
	case RouterLSAtype:
		if lsa, ok := lsa.Content.(RouterLSA); ok {
			data[offset] = lsa.Flags
			binary.BigEndian.PutUint32(data[offset+1:offset+5], lsa.Options<<8)
			offset += 4
			for _, router := range lsa.Routers {
				data[offset] = router.Type
				binary.BigEndian.PutUint16(data[offset+2:offset+4], router.Metric)
				binary.BigEndian.PutUint32(data[offset+4:offset+8], router.InterfaceID)
				binary.BigEndian.PutUint32(data[offset+8:offset+12], router.NeighborInterfaceID)
				binary.BigEndian.PutUint32(data[offset+12:offset+16], router.NeighborRouterID)
				offset += 16
			}
			return nil
		}
		return fmt.Errorf("Invalid Content: want RouterLSA, got %s", reflect.TypeOf(lsa))
	case NetworkLSAtype:
		if _, ok := lsa.Content.(NetworkLSA); ok {
			return nil
		}
		return fmt.Errorf("Invalid Content: want NetworkLSA, got %s", reflect.TypeOf(lsa))
	case InterAreaPrefixLSAtype:
		if lsa, ok := lsa.Content.(InterAreaPrefixLSA); ok {
			binary.BigEndian.PutUint32(data[offset+1:offset+5], lsa.Metric<<8)
			data[offset+4] = lsa.PrefixLength
			data[offset+5] = lsa.PrefixOptions
			copy(data[offset+8:offset+8+len(lsa.AddressPrefix)], lsa.AddressPrefix)
			return nil
		}
		return fmt.Errorf("Invalid Content: want InterAreaPrefixLSA, got %s", reflect.TypeOf(lsa))
	case InterAreaRouterLSAtype:
		if _, ok := lsa.Content.(InterAreaRouterLSA); ok {
			return nil
		}
		return fmt.Errorf("Invalid Content: want InterAreaRouterLSA, got %s", reflect.TypeOf(lsa))
	case ASExternalLSAtype:
		fallthrough
	case NSSALSAtype:
		if _, ok := lsa.Content.(ASExternalLSA); ok {
			return nil
		}
		return fmt.Errorf("Invalid Content: want ASExternalLSA, got %s", reflect.TypeOf(lsa))
	case LinkLSAtype:
		if lsa, ok := lsa.Content.(LinkLSA); ok {
			data[offset] = lsa.RtrPriority
			binary.BigEndian.PutUint32(data[offset+1:offset+5], lsa.Options<<8)
			copy(data[offset+4:offset+20], lsa.LinkLocalAddress)
			binary.BigEndian.PutUint32(data[offset+20:offset+24], lsa.NumOfPrefixes)
			offset += 24
			for _, prefix := range lsa.Prefixes {
				data[offset] = prefix.PrefixLength
				data[offset+1] = prefix.PrefixOptions
				copy(data[offset+4:offset+4+int(prefix.PrefixLength)/8], prefix.AddressPrefix)
				offset += 4 + int(prefix.PrefixLength)/8
			}
			return nil
		}
		return fmt.Errorf("Invalid Content: want LinkLSA, got %s", reflect.TypeOf(lsa))
	case IntraAreaPrefixLSAtype:
		if lsa, ok := lsa.Content.(IntraAreaPrefixLSA); ok {
			binary.BigEndian.PutUint16(data[offset:offset+2], lsa.NumOfPrefixes)
			binary.BigEndian.PutUint16(data[offset+2:offset+4], lsa.RefLSType)
			binary.BigEndian.PutUint32(data[offset+4:offset+8], lsa.RefLinkStateID)
			binary.BigEndian.PutUint32(data[offset+8:offset+12], lsa.RefAdvRouter)
			offset += 12
			for _, prefix := range lsa.Prefixes {
				data[offset] = prefix.PrefixLength
				data[offset+1] = prefix.PrefixOptions
				binary.BigEndian.PutUint16(data[offset+2:offset+4], prefix.Metric)
				copy(data[offset+4:offset+4+int(prefix.PrefixLength)/8], prefix.AddressPrefix)
				offset += 4 + int(prefix.PrefixLength)/8
			}
			return nil
		}
		return fmt.Errorf("Invalid Content: want IntraAreaPrefixLSA, got %s", reflect.TypeOf(lsa))
	default:
		return fmt.Errorf("Unknown LSA Type")
	}
}

// getLSAs parses the LSA information from the packet for OSPFv3
func getLSAs(num uint32, data []byte) ([]LSA, error) {
	var lsas []LSA
	var i uint32 = 0
	var offset uint32 = 0
	for ; i < num; i++ {
		var content interface{}
		lstype := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		lsalength := binary.BigEndian.Uint16(data[offset+18 : offset+20])

		content, err := extractLSAInformation(lstype, lsalength, data[offset:])
		if err != nil {
			return nil, fmt.Errorf("Could not extract Link State type.")
		}
		lsa := LSA{
			LSAheader: LSAheader{
				LSAge:       binary.BigEndian.Uint16(data[offset : offset+2]),
				LSType:      lstype,
				LinkStateID: binary.BigEndian.Uint32(data[offset+4 : offset+8]),
				AdvRouter:   binary.BigEndian.Uint32(data[offset+8 : offset+12]),
				LSSeqNumber: binary.BigEndian.Uint32(data[offset+12 : offset+16]),
				LSChecksum:  binary.BigEndian.Uint16(data[offset+16 : offset+18]),
				Length:      lsalength,
			},
			Content: content,
		}
		lsas = append(lsas, lsa)
		offset += uint32(lsalength)
	}
	return lsas, nil
}

// DecodeFromBytes decodes the given bytes into the OSPF layer.
func (ospf *OSPFv2) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 24 {
		return fmt.Errorf("Packet too smal for OSPF Version 2")
	}

	ospf.BaseLayer = BaseLayer{Contents: data[:len(data)]}

	ospf.Version = uint8(data[0])
	ospf.Type = OSPFType(data[1])
	ospf.PacketLength = binary.BigEndian.Uint16(data[2:4])
	ospf.RouterID = binary.BigEndian.Uint32(data[4:8])
	ospf.AreaID = binary.BigEndian.Uint32(data[8:12])
	ospf.Checksum = binary.BigEndian.Uint16(data[12:14])
	ospf.AuType = binary.BigEndian.Uint16(data[14:16])
	ospf.Authentication = binary.BigEndian.Uint64(data[16:24])

	switch ospf.Type {
	case OSPFHello:
		var neighbors []uint32
		for i := 44; uint16(i+4) <= ospf.PacketLength; i += 4 {
			neighbors = append(neighbors, binary.BigEndian.Uint32(data[i:i+4]))
		}
		ospf.Content = HelloPkgV2{
			NetworkMask: binary.BigEndian.Uint32(data[24:28]),
			HelloPkg: HelloPkg{
				HelloInterval:            binary.BigEndian.Uint16(data[28:30]),
				Options:                  uint32(data[30]),
				RtrPriority:              uint8(data[31]),
				RouterDeadInterval:       binary.BigEndian.Uint32(data[32:36]),
				DesignatedRouterID:       binary.BigEndian.Uint32(data[36:40]),
				BackupDesignatedRouterID: binary.BigEndian.Uint32(data[40:44]),
				NeighborID:               neighbors,
			},
		}
	case OSPFDatabaseDescription:
		var lsas []LSAheader
		for i := 32; uint16(i+20) <= ospf.PacketLength; i += 20 {
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
			InterfaceMTU: binary.BigEndian.Uint16(data[24:26]),
			Options:      uint32(data[26]),
			Flags:        uint16(data[27]),
			DDSeqNumber:  binary.BigEndian.Uint32(data[28:32]),
			LSAinfo:      lsas,
		}
	case OSPFLinkStateRequest:
		var lsrs []LSReq
		for i := 24; uint16(i+12) <= ospf.PacketLength; i += 12 {
			lsr := LSReq{
				LSType:    binary.BigEndian.Uint16(data[i+2 : i+4]),
				LSID:      binary.BigEndian.Uint32(data[i+4 : i+8]),
				AdvRouter: binary.BigEndian.Uint32(data[i+8 : i+12]),
			}
			lsrs = append(lsrs, lsr)
		}
		ospf.Content = lsrs
	case OSPFLinkStateUpdate:
		num := binary.BigEndian.Uint32(data[24:28])

		lsas, err := getLSAsv2(num, data[28:])
		if err != nil {
			return fmt.Errorf("Cannot parse Link State Update packet: %v", err)
		}
		ospf.Content = LSUpdate{
			NumOfLSAs: num,
			LSAs:      lsas,
		}
	case OSPFLinkStateAcknowledgment:
		var lsas []LSAheader
		for i := 24; uint16(i+20) <= ospf.PacketLength; i += 20 {
			lsa := LSAheader{
				LSAge:       binary.BigEndian.Uint16(data[i : i+2]),
				LSOptions:   data[i+2],
				LSType:      uint16(data[i+3]),
				LinkStateID: binary.BigEndian.Uint32(data[i+4 : i+8]),
				AdvRouter:   binary.BigEndian.Uint32(data[i+8 : i+12]),
				LSSeqNumber: binary.BigEndian.Uint32(data[i+12 : i+16]),
				LSChecksum:  binary.BigEndian.Uint16(data[i+16 : i+18]),
				Length:      binary.BigEndian.Uint16(data[i+18 : i+20]),
			}
			lsas = append(lsas, lsa)
		}
		ospf.Content = lsas
	}
	return nil
}

// DecodeFromBytes decodes the given bytes into the OSPF layer.
func (ospf *OSPFv3) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	if len(data) < 16 {
		return fmt.Errorf("Packet too smal for OSPF Version 3")
	}

	ospf.BaseLayer = BaseLayer{Contents: data[:len(data)]}

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
			RouterDeadInterval:       uint32(binary.BigEndian.Uint16(data[26:28])),
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
	case OSPFLinkStateUpdate:
		num := binary.BigEndian.Uint32(data[16:20])
		lsas, err := getLSAs(num, data[20:])
		if err != nil {
			return fmt.Errorf("Cannot parse Link State Update packet: %v", err)
		}
		ospf.Content = LSUpdate{
			NumOfLSAs: num,
			LSAs:      lsas,
		}

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

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (ospf *OSPFv2) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return nil
}

func (ospf *OSPFv3) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	size := 16
	switch ospf.Type {
	case OSPFHello:
		if lsa, ok := ospf.Content.(HelloPkg); ok {
			size += 20 + len(lsa.NeighborID)*4
			bytes, err := b.PrependBytes(size)
			if err != nil {
				return err
			}
			if opts.FixLengths {
				ospf.PacketLength = uint16(size)
			}
			bytes[0] = 0x03
			bytes[1] = uint8(OSPFHello)
			binary.BigEndian.PutUint16(bytes[2:4], uint16(size))
			binary.BigEndian.PutUint32(bytes[4:8], ospf.RouterID)
			binary.BigEndian.PutUint32(bytes[8:12], ospf.AreaID)

			binary.BigEndian.PutUint32(bytes[16:20], lsa.InterfaceID)
			bytes[20] = lsa.RtrPriority
			binary.BigEndian.PutUint32(bytes[21:25], lsa.Options<<8)
			binary.BigEndian.PutUint16(bytes[24:26], lsa.HelloInterval)
			binary.BigEndian.PutUint16(bytes[26:28], uint16(lsa.RouterDeadInterval))
			binary.BigEndian.PutUint32(bytes[28:32], lsa.DesignatedRouterID)
			binary.BigEndian.PutUint32(bytes[32:36], lsa.BackupDesignatedRouterID)
			for i := 0; i < len(lsa.NeighborID); i++ {
				binary.BigEndian.PutUint32(bytes[36+i*4:40+i*4], lsa.NeighborID[0])
			}
			if opts.ComputeChecksums {
				if opts.ComputeChecksums {
					bytes[12] = 0
					bytes[13] = 0
					csum, err := ospf.computeChecksum(b.Bytes(), IPProtocolOSPF)
					if err != nil {
						return err
					}
					ospf.Checksum = csum
				}
				binary.BigEndian.PutUint16(bytes[12:14], ospf.Checksum)
			} else {
				binary.BigEndian.PutUint16(bytes[12:14], ospf.Checksum)
			}
			return nil
		}
		return fmt.Errorf("Invalid Content")
	case OSPFDatabaseDescription:
		if lsa, ok := ospf.Content.(DbDescPkg); ok {
			size += 12 + len(lsa.LSAinfo)*20
			bytes, err := b.PrependBytes(size)
			if err != nil {
				return err
			}
			if opts.FixLengths {
				ospf.PacketLength = uint16(size)
			}
			bytes[0] = 0x03
			bytes[1] = uint8(OSPFDatabaseDescription)
			binary.BigEndian.PutUint16(bytes[2:4], uint16(size))
			binary.BigEndian.PutUint32(bytes[4:8], ospf.RouterID)
			binary.BigEndian.PutUint32(bytes[8:12], ospf.AreaID)

			binary.BigEndian.PutUint32(bytes[17:21], lsa.Options<<8)
			binary.BigEndian.PutUint16(bytes[20:22], lsa.InterfaceMTU)
			binary.BigEndian.PutUint16(bytes[22:24], lsa.Flags)
			binary.BigEndian.PutUint32(bytes[24:28], lsa.DDSeqNumber)

			for i, lsaHeader := range lsa.LSAinfo {
				o := i * 20
				binary.BigEndian.PutUint16(bytes[o:o+2], lsaHeader.LSAge)
				binary.BigEndian.PutUint16(bytes[o+2:o+4], lsaHeader.LSType)
				binary.BigEndian.PutUint32(bytes[o+4:o+8], lsaHeader.LinkStateID)
				binary.BigEndian.PutUint32(bytes[o+8:o+12], lsaHeader.AdvRouter)
				binary.BigEndian.PutUint32(bytes[o+12:o+16], lsaHeader.LSSeqNumber)
				binary.BigEndian.PutUint16(bytes[o+16:o+18], lsaHeader.LSChecksum)
				binary.BigEndian.PutUint16(bytes[o+18:o+20], lsaHeader.LSType)
			}
			if opts.ComputeChecksums {
				if opts.ComputeChecksums {
					bytes[12] = 0
					bytes[13] = 0
					csum, err := ospf.computeChecksum(b.Bytes(), IPProtocolOSPF)
					if err != nil {
						return err
					}
					ospf.Checksum = csum
				}
				binary.BigEndian.PutUint16(bytes[12:14], ospf.Checksum)
			} else {
				binary.BigEndian.PutUint16(bytes[12:14], ospf.Checksum)
			}
			return nil
		}
		return fmt.Errorf("Invalid Content")
	case OSPFLinkStateRequest:
		if lsas, ok := ospf.Content.([]LSReq); ok {
			size += len(lsas) * 12
			bytes, err := b.PrependBytes(size)
			if err != nil {
				return err
			}
			if opts.FixLengths {
				ospf.PacketLength = uint16(size)
			}
			bytes[0] = 0x03
			bytes[1] = uint8(OSPFLinkStateRequest)
			binary.BigEndian.PutUint16(bytes[2:4], uint16(size))
			binary.BigEndian.PutUint32(bytes[4:8], ospf.RouterID)
			binary.BigEndian.PutUint32(bytes[8:12], ospf.AreaID)

			for i, lsReq := range lsas {
				o := i*12 + 16
				binary.BigEndian.PutUint16(bytes[o+2:o+4], lsReq.LSType)
				binary.BigEndian.PutUint32(bytes[o+4:o+8], lsReq.LSID)
				binary.BigEndian.PutUint32(bytes[o+8:o+12], lsReq.AdvRouter)
			}
			if opts.ComputeChecksums {
				if opts.ComputeChecksums {
					bytes[12] = 0
					bytes[13] = 0
					csum, err := ospf.computeChecksum(b.Bytes(), IPProtocolOSPF)
					if err != nil {
						return err
					}
					ospf.Checksum = csum
				}
				binary.BigEndian.PutUint16(bytes[12:14], ospf.Checksum)
			} else {
				binary.BigEndian.PutUint16(bytes[12:14], ospf.Checksum)
			}
			return nil
		}
		return fmt.Errorf("Invalid Content")
	case OSPFLinkStateUpdate:
		if lsUpdate, ok := ospf.Content.(LSUpdate); ok {
			size += 4
			for _, lsa := range lsUpdate.LSAs {
				lsaSize, err := getArchivedLSAInformationSize(lsa)
				if err != nil {
					return err
				}
				size += lsaSize
			}
			bytes, err := b.PrependBytes(size)
			if err != nil {
				return err
			}
			if opts.FixLengths {
				ospf.PacketLength = uint16(size)
			}
			bytes[0] = 0x03
			bytes[1] = uint8(OSPFLinkStateUpdate)
			binary.BigEndian.PutUint16(bytes[2:4], uint16(size))
			binary.BigEndian.PutUint32(bytes[4:8], ospf.RouterID)
			binary.BigEndian.PutUint32(bytes[8:12], ospf.AreaID)
			binary.BigEndian.PutUint32(bytes[16:20], uint32(len(lsUpdate.LSAs)))

			offset := 20
			for _, lsa := range lsUpdate.LSAs {
				lsaSize, err := getArchivedLSAInformationSize(lsa)
				if err != nil {
					return err
				}
				err = archiveLSAInformation(lsa.LSType, lsa, lsaSize, bytes, offset)
				if err != nil {
					return err
				}
				offset += lsaSize
			}
			if opts.ComputeChecksums {
				if opts.ComputeChecksums {
					bytes[12] = 0
					bytes[13] = 0
					csum, err := ospf.computeChecksum(b.Bytes(), IPProtocolOSPF)
					if err != nil {
						return err
					}
					ospf.Checksum = csum
				}
				binary.BigEndian.PutUint16(bytes[12:14], ospf.Checksum)
			} else {
				binary.BigEndian.PutUint16(bytes[12:14], ospf.Checksum)
			}
			return nil
		}
		return fmt.Errorf("Invalid Content")
	case OSPFLinkStateAcknowledgment:
		if lsas, ok := ospf.Content.([]LSAheader); ok {
			size += len(lsas) * 20
			bytes, err := b.PrependBytes(size)
			if err != nil {
				return err
			}
			if opts.FixLengths {
				ospf.PacketLength = uint16(size)
			}
			bytes[0] = 0x03
			bytes[1] = uint8(OSPFLinkStateAcknowledgment)
			binary.BigEndian.PutUint16(bytes[2:4], uint16(size))
			binary.BigEndian.PutUint32(bytes[4:8], ospf.RouterID)
			binary.BigEndian.PutUint32(bytes[8:12], ospf.AreaID)

			for i, lsaHeader := range lsas {
				o := i*20 + 16
				binary.BigEndian.PutUint16(bytes[o:o+2], lsaHeader.LSAge)
				binary.BigEndian.PutUint16(bytes[o+2:o+4], lsaHeader.LSType)
				binary.BigEndian.PutUint32(bytes[o+4:o+8], lsaHeader.LinkStateID)
				binary.BigEndian.PutUint32(bytes[o+8:o+12], lsaHeader.AdvRouter)
				binary.BigEndian.PutUint32(bytes[o+12:o+16], lsaHeader.LSSeqNumber)
				binary.BigEndian.PutUint16(bytes[o+16:o+18], lsaHeader.LSChecksum)
				binary.BigEndian.PutUint16(bytes[o+18:o+20], lsaHeader.Length)
			}
			if opts.ComputeChecksums {
				if opts.ComputeChecksums {
					bytes[12] = 0
					bytes[13] = 0
					csum, err := ospf.computeChecksum(b.Bytes(), IPProtocolOSPF)
					if err != nil {
						return err
					}
					ospf.Checksum = csum
				}
				binary.BigEndian.PutUint16(bytes[12:14], ospf.Checksum)
			} else {
				binary.BigEndian.PutUint16(bytes[12:14], ospf.Checksum)
			}
			return nil
		}
		return fmt.Errorf("Invalid Content")
	default:
		return fmt.Errorf("Unknown OSPFType: %d", ospf.Type)
	}
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

func (ospf *OSPFv2) Payload() []byte {
	return nil
}

func (ospf *OSPFv3) Payload() []byte {
	return nil
}

func decodeOSPF(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 14 {
		return fmt.Errorf("Packet too smal for OSPF")
	}

	switch uint8(data[0]) {
	case 2:
		o := &OSPFv2{}
		err := o.DecodeFromBytes(data, p)
		if err != nil {
			return err
		}
		p.AddLayer(o)
		p.SetApplicationLayer(o)
		return nil
	case 3:
		o := &OSPFv3{}
		err := o.DecodeFromBytes(data, p)
		if err != nil {
			return err
		}
		p.AddLayer(o)
		p.SetApplicationLayer(o)
		return nil
	default:
	}

	return fmt.Errorf("Unable to determine OSPF type.")
}
