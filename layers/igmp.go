// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"net"
	"time"
)

type IGMPType uint8

const (
	MembershipQuery    IGMPType = 0x11 // General or group specific query
	MembershipReportV1 IGMPType = 0x12 // Version 1 Membership Report
	MembershipReportV2 IGMPType = 0x16 // Version 2 Membership Report
	LeaveGroup         IGMPType = 0x17 // Leave Group
	MembershipReportV3 IGMPType = 0x22 // Version 3 Membership Report
)

// String conversions for IGMP message types
func (i IGMPType) String() string {
	switch i {
	case MembershipQuery:
		return "IGMP Membership Query"
	case MembershipReportV1:
		return "IGMPv1 Membership Report"
	case MembershipReportV2:
		return "IGMPv2 Membership Report"
	case MembershipReportV3:
		return "IGMPv3 Membership Report"
	case LeaveGroup:
		return "Leave Group"
	default:
		return ""
	}
}

type IGMPQuery interface {
	decodeResponse(data []byte) error
}

// IGMP is the packet structure for IGMP messages.
type IGMP struct {
	BaseLayer
	Type    IGMPType  // IGMP message type
	Message IGMPQuery // Container for message payload
	Version uint8     // IGMP protocol version
}

type GroupRecordType uint8

const (
	IsIn  GroupRecordType = 0x01 // Type MODE_IS_INCLUDE, source addresses x
	IsEx  GroupRecordType = 0x02 // Type MODE_IS_EXCLUDE, source addresses x
	ToIn  GroupRecordType = 0x03 // Type CHANGE_TO_INCLUDE_MODE, source addresses x
	ToEx  GroupRecordType = 0x04 // Type CHANGE_TO_EXCLUDE_MODE, source addresses x
	Allow GroupRecordType = 0x05 // Type ALLOW_NEW_SOURCES, source addresses x
	Block GroupRecordType = 0x06 // Type BLOCK_OLD_SOURCES, source addresses x
)

func (i GroupRecordType) String() string {
	switch i {
	case IsIn:
		return "MODE_IS_INCLUDE"
	case IsEx:
		return "MODE_IS_EXCLUDE"
	case ToIn:
		return "CHANGE_TO_INCLUDE_MODE"
	case ToEx:
		return "CHANGE_TO_EXCLUDE_MODE"
	case Allow:
		return "ALLOW_NEW_SOURCES"
	case Block:
		return "BLOCK_OLD_SOURCES"
	default:
		return ""
	}
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Type     | Max Resp Time |           Checksum            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Group Address                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// IGMPv1or2 stores header details for an IGMPv1 or IGMPv2 packet.
type IGMPv1or2 struct {
	MaxRespTime  time.Duration // meaningful only in Membership Query messages
	Checksum     uint16        // 16-bit checksum of entire ip payload
	GroupAddress net.IP        // either 0 or an IP multicast address
}

// decodeResponse dissects IGMPv1 or IGMPv2 packet.
func (i *IGMPv1or2) decodeResponse(data []byte) error {
	i.MaxRespTime = igmpTimeDecode(data[1])
	i.Checksum = binary.BigEndian.Uint16(data[2:4])
	i.GroupAddress = net.IP(data[4:8])

	return nil
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Type = 0x22  |    Reserved   |           Checksum            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Reserved            |  Number of Group Records (M)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// .                        Group Record [1]                       .
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// .                        Group Record [2]                       .
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// .                        Group Record [M]                       .
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// IGMPv3MembershipReport stores bytes 2: of the V3 Membership Report packet
type IGMPv3MembershipReport struct {
	Checksum             uint16 // 16-bit checksum of entire ip payload
	NumberofGroupRecords uint16
	GroupRecords         []GroupRecord
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Multicast Address                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address [1]                      |
// +-                                                             -+
// |                       Source Address [2]                      |
// +-                                                             -+
// |                       Source Address [N]                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// .                         Auxiliary Data                        .
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// GroupRecord stores individual group records for a V3 Membership Report message.
type GroupRecord struct {
	Type             GroupRecordType
	AuxDataLen       uint8 // this should always be 0 as per IGMPv3 spec.
	NumberOfSources  uint16
	MulticastAddress net.IP
	SourceAddresses  []net.IP
	AuxData          uint32 // NOT USED
}

// decodeResponse decodes an IGMPv3MembershipReport message.
func (i *IGMPv3MembershipReport) decodeResponse(data []byte) error {
	i.Checksum = binary.BigEndian.Uint16(data[2:4])
	i.NumberofGroupRecords = binary.BigEndian.Uint16(data[6:8])

	for j := 0; j < int(i.NumberofGroupRecords); j++ {
		var gr GroupRecord
		gr.Type = GroupRecordType(data[8])
		gr.AuxDataLen = data[9]
		gr.NumberOfSources = binary.BigEndian.Uint16(data[10:12])
		gr.MulticastAddress = net.IP(data[12:16])

		// append source address records.
		for i := 0; i < int(gr.NumberOfSources); i++ {
			gr.SourceAddresses = append(gr.SourceAddresses, net.IP(data[16+i*4:20+i*4]))
		}

		i.GroupRecords = append(i.GroupRecords, gr)
	}
	return nil
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Type = 0x11  | Max Resp Code |           Checksum            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Group Address                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address [1]                      |
// +-                                                             -+
// |                       Source Address [2]                      |
// +-                              .                              -+
// |                       Source Address [N]                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IGMPv3MembershipQuery struct {
	MaxResponseTime time.Duration // IGMP Max response code/time
	Checksum        uint16        // 16-bit checksum of entire ip payload
	GroupAddress    net.IP        // IP multicast address.
	SFlag           bool          // Suppress Router-Side Processing
	QRV             uint8         // Querier's Robustness Variable
	QQIC            time.Duration // Querier's Query Interval Code
	NumberofSources uint16
	SourceAddresses []net.IP
}

func (i *IGMPv3MembershipQuery) decodeResponse(data []byte) error {

	i.Checksum = binary.BigEndian.Uint16(data[2:4])
	i.SFlag = data[8]&0x8 != 0
	i.GroupAddress = net.IP(data[4:8])
	i.QRV = data[8] & 0x7
	i.QQIC = igmpTimeDecode(data[9])
	i.NumberofSources = binary.BigEndian.Uint16(data[10:12])

	for j := 0; j < int(i.NumberofSources); j++ {
		i.SourceAddresses = append(i.SourceAddresses, net.IP(data[12+j*4:16+j*4]))
	}

	return nil
}

// LayerType returns LayerTypeIGMP
func (i *IGMP) LayerType() gopacket.LayerType { return LayerTypeIGMP }

// igmpTimeDecode decodes the duration created by the given byte, using the
// algorithm in http://www.rfc-base.org/txt/rfc-3376.txt section 4.1.1.
func igmpTimeDecode(t uint8) time.Duration {
	if t&0x80 == 0 {
		return time.Millisecond * 100 * time.Duration(t)
	}
	mant := (t & 0x70) >> 4
	exp := t & 0x0F
	return time.Millisecond * 100 * time.Duration((mant|0x10)<<(exp+3))
}

// DecodeFromBytes decodes the given bytes into this layer.
func (i *IGMP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	// common IGMP header values between versions 1..3 of IGMP specification..
	i.Type = IGMPType(data[0])

	switch i.Type {

	case MembershipQuery:

		// IGMPv3 Membership Query payload is >= 12
		if len(data) >= 12 {
			i.Version = 3
			i.Message = new(IGMPv3MembershipQuery)
			i.Message.decodeResponse(data)

		} else if len(data) == 8 {

			if data[1] == 0x00 {
				i.Version = 1 // IGMPv1 has a query length of 8 and MaxResp = 0
			} else {
				i.Version = 2 // IGMPv2 has a query length of 8 and MaxResp != 0
			}

			i.Message = new(IGMPv1or2)
			i.Message.decodeResponse(data)
		}

	case MembershipReportV3:
		i.Version = 3
		i.Message = new(IGMPv3MembershipReport)
		i.Message.decodeResponse(data)

	case MembershipReportV1:
		i.Version = 1
		i.Message = new(IGMPv1or2)
		i.Message.decodeResponse(data)

	case LeaveGroup, MembershipReportV2:
		// leave group and Query Report v2 used in IGMPv2 only.
		i.Version = 2
		i.Message = new(IGMPv1or2)
		i.Message.decodeResponse(data)
	}

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (i *IGMP) CanDecode() gopacket.LayerClass {
	return LayerTypeIGMP
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (i *IGMP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func decodeIGMP(data []byte, p gopacket.PacketBuilder) error {
	i := &IGMP{}
	return decodingLayerDecoder(i, data, p)
}
