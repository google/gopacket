// Copyright 2014 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

/*
This layer decodes SFlow version 5 datagrams.

The specification can be found here: http://sflow.org/sflow_version_5.txt

Additional developer information about sflow can be found at:
http://sflow.org/developers/specifications.php

And SFlow in general:
http://sflow.org/index.php

Two forms of sample data are defined: compact and expanded. The
Specification has this to say:

    Compact and expand forms of counter and flow samples are defined.
    An agent must not mix compact/expanded encodings.  If an agent
    will never use ifIndex numbers >= 2^24 then it must use compact
    encodings for all interfaces.  Otherwise the expanded formats must
    be used for all interfaces.

This decoder only supports the compact form, because that is the only
one for which data was avaialble.

The datagram is composed of one or more samples of type flow or counter,
and each sample is composed of one or more records describing the sample.
A sample is a single instance of sampled inforamtion, and each record in
the sample gives additional / supplimentary information about the sample.

The following sample record types are supported:

	Raw Packet Header
	opaque = flow_data; enterprise = 0; format = 1

	Extended Switch Data
	opaque = flow_data; enterprise = 0; format = 1001

	Extended Router Data
	opaque = flow_data; enterprise = 0; format = 1002

	Extended Gateway Data
	opaque = flow_data; enterprise = 0; format = 1003

	Extended User Data
	opaque = flow_data; enterprise = 0; format = 1004

	Extended URL Data
	opaque = flow_data; enterprise = 0; format = 1005

The following types of counter records are supported:

	Generic Interface Counters - see RFC 2233
	opaque = counter_data; enterprise = 0; format = 1

	Ethernet Interface Counters - see RFC 2358
	opaque = counter_data; enterprise = 0; format = 2

SFlow is encoded using XDR (RFC4506). There are a few places
where the standard 4-byte fields are partitioned into two
bitfields of different lengths. I'm not sure why the designers
chose to pack together two values like this in some places, and
in others they use the entire 4-byte value to store a number that
will never be more than a few bits. In any case, there are a couple
of types defined to handle the decoding of these bitfields, and
that's why they're there. */

package layers

import (
	"bytes"
	"code.google.com/p/gopacket"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SFlowSample is a container that holds at least one record, plus metadata
// about the sample(s). Samples can be of two general types: flow samples
// and counter samples. (There are 'extended' versions of both of these
// but this decoder does not support them because I couldn't get any example
// data to test with.)
type SFlowSample interface {
	GetRecords() []SFlowRecord
	GetType() SFlowSampleType
}

// SFlowRecord holds both flow sample records and counter sample records.
// A Record is the structure that actually holds the sampled data
// and / or counters.
type SFlowRecord interface {
}

// SFlowDataSource encodes a 2-bit SFlowSourceFormat in its most significant
// 2 bits, and an SFlowSourceValue in its least significant 30 bits.
// These types and values define the meaning of the inteface information
// presented in the sample metadata.
type SFlowDataSource int32

func (sdc SFlowDataSource) decode() (SFlowSourceFormat, SFlowSourceValue) {
	leftField := sdc >> 30
	rightField := uint32(0x3FFFFFFF) & uint32(sdc)
	return SFlowSourceFormat(leftField), SFlowSourceValue(rightField)
}

type SFlowSourceFormat uint32

type SFlowSourceValue uint32

const (
	SFlowTypeSingleInterface      SFlowSourceFormat = 0
	SFlowTypePacketDiscarded      SFlowSourceFormat = 1
	SFlowTypeMultipleDestinations SFlowSourceFormat = 2
)

func (sdf SFlowSourceFormat) String() string {
	switch sdf {
	case SFlowTypeSingleInterface:
		return "Single Interface"
	case SFlowTypePacketDiscarded:
		return "Packet Discarded"
	case SFlowTypeMultipleDestinations:
		return "Multiple Destinations"
	default:
		return ""
	}
}

func decodeSFlow(data []byte, p gopacket.PacketBuilder) error {
	s := &SFlowDatagram{}
	err := s.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(s)
	p.SetApplicationLayer(s)
	return nil
}

// SFlowDatagram is the outermost container which holds some basic information
// about the reporting agent, and holds at least one sample record
type SFlowDatagram struct {
	BaseLayer

	DatagramVersion uint32
	AgentAddress    net.IP
	SubAgentID      uint32
	SequenceNumber  uint32
	AgentUptime     uint32
	SampleCount     uint32
	Samples         []SFlowSample
}

// An SFlow  datagram's outer container has the following
// structure:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |           int sFlow version (2|4|5)           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |   int IP version of the Agent (1=v4|2=v6)     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /    Agent IP address (v4=4byte|v6=16byte)      /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |               int sub agent id                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |         int datagram sequence number          |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |            int switch uptime in ms            |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |          int n samples in datagram            |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /                  n samples                    /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// SFlowDataFormat encodes the EnterpriseID in the most
// significant 12 bits, and the SampleType in the least significant
// 20 bits.
type SFlowDataFormat uint32

func (sdf SFlowDataFormat) decode() (SFlowEnterpriseID, SFlowSampleType) {
	leftField := sdf >> 12
	rightField := uint32(0xFFFFF) & uint32(sdf)
	return SFlowEnterpriseID(leftField), SFlowSampleType(rightField)
}

// SFlowEnterpriseID is used to differentiate between the
// official SFlow standard, and other, vendor-specific
// types of flow data. (Similiar to SNMP's enterprise MIB
// OIDs) Only the office SFlow Enterprise ID is decoded
// here.
type SFlowEnterpriseID uint32

const (
	SFlowStandard SFlowEnterpriseID = 0
)

func (eid SFlowEnterpriseID) String() string {
	switch eid {
	case SFlowStandard:
		return "Standard SFlow"
	default:
		return ""
	}
}

func (eid SFlowEnterpriseID) GetType() SFlowEnterpriseID {
	return SFlowStandard
}

// SFlowSampleType specifies the type of sample. Only flow samples
// and counter samples are supported
type SFlowSampleType uint32

const (
	SFlowTypeFlowSample            SFlowSampleType = 1
	SFlowTypeCounterSample         SFlowSampleType = 2
	SFlowTypeExpandedFlowSample    SFlowSampleType = 3
	SFlowTypeExpandedCounterSample SFlowSampleType = 4
)

func (st SFlowSampleType) GetType() SFlowSampleType {
	switch st {
	case SFlowTypeFlowSample:
		return SFlowTypeFlowSample
	case SFlowTypeCounterSample:
		return SFlowTypeCounterSample
	case SFlowTypeExpandedFlowSample:
		return SFlowTypeExpandedFlowSample
	case SFlowTypeExpandedCounterSample:
		return SFlowTypeExpandedCounterSample
	default:
		panic("Invalid Sample Type")
	}
}

func (st SFlowSampleType) String() string {
	switch st {
	case SFlowTypeFlowSample:
		return "Flow Sample"
	case SFlowTypeCounterSample:
		return "Counter Sample"
	case SFlowTypeExpandedFlowSample:
		return "Expanded Flow Sample"
	case SFlowTypeExpandedCounterSample:
		return "Expanded Counter Sample"
	default:
		return ""
	}

}

func (s *SFlowDatagram) LayerType() gopacket.LayerType { return LayerTypeSFlow }

func (d *SFlowDatagram) Payload() []byte { return nil }

func (d *SFlowDatagram) CanDecode() gopacket.LayerClass { return LayerTypeSFlow }

func (d *SFlowDatagram) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

// SFlowIPType determines what form the IP address being decoded will
// take. This is an XDR union type allowing for both IPv4 and IPv6
type SFlowIPType uint32

const (
	SFlowIPv4 SFlowIPType = 1
	SFlowIPv6 SFlowIPType = 2
)

func (s SFlowIPType) String() string {
	switch s {
	case SFlowIPv4:
		return "IPv4"
	case SFlowIPv6:
		return "IPv6"
	default:
		return ""
	}
}

func (s SFlowIPType) decodeIP(r io.Reader) net.IP {
	var length int
	switch SFlowIPType(s) {
	case SFlowIPv4:
		length = 4
	case SFlowIPv6:
		length = 16
	default:
		return nil
	}

	buff := make([]byte, length)
	r.Read(buff)

	return buff

}

func (s *SFlowDatagram) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	r := bytes.NewReader(data)
	var agentAddressType SFlowIPType

	binary.Read(r, binary.BigEndian, &s.DatagramVersion)
	binary.Read(r, binary.BigEndian, &agentAddressType)
	s.AgentAddress = agentAddressType.decodeIP(r)
	binary.Read(r, binary.BigEndian, &s.SubAgentID)
	binary.Read(r, binary.BigEndian, &s.SequenceNumber)
	binary.Read(r, binary.BigEndian, &s.AgentUptime)
	binary.Read(r, binary.BigEndian, &s.SampleCount)

	if s.SampleCount < 1 {
		return fmt.Errorf("SFlow Datagram has invalid sample length: %d", s.SampleCount)
	}

	for i := uint32(0); i < s.SampleCount; i++ {
		var sdf SFlowDataFormat
		binary.Read(r, binary.BigEndian, &sdf)
		_, sampleType := sdf.decode()
		r.Seek(-4, 1)

		switch sampleType {
		case SFlowTypeFlowSample:
			if flowSample, err := decodeFlowSample(r); err == nil {
				s.Samples = append(s.Samples, flowSample)
			} else {
				return err
			}
		case SFlowTypeCounterSample:
			if counterSample, err := decodeCounterSample(r); err == nil {
				s.Samples = append(s.Samples, counterSample)
			} else {
				return err
			}

		case SFlowTypeExpandedFlowSample:
			// TODO
			return fmt.Errorf("Unsupported SFlow sample type TypeExpandedFlowSample")
		case SFlowTypeExpandedCounterSample:
			// TODO
			return fmt.Errorf("Unsupported SFlow sample type TypeExpandedCounterSample")
		default:
			return fmt.Errorf("Unsupported SFlow sample type %d", sampleType)
		}

	}

	return nil

}

// SFlowFlowSample represents a sampled packet and contains
// one or more records describing the packet
type SFlowFlowSample struct {
	EnterpriseID    SFlowEnterpriseID
	Format          SFlowSampleType
	SampleLength    uint32
	SequenceNumber  uint32
	SourceIDClass   SFlowSourceFormat
	SourceIDIndex   SFlowSourceValue
	SamplingRate    uint32
	SamplePool      uint32
	Dropped         uint32
	InputInterface  uint32
	OutputInterface uint32
	RecordCount     uint32
	Records         []SFlowRecord
}

// Flow samples have the following structure. Note
// the bit fields to encode the Enterprise ID and the
// Flow record format:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  sample length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |          int sample sequence number           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |id type |       src id index value             |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |               int sampling rate               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                int sample pool                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    int drops                  |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 int input ifIndex             |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                int output ifIndex             |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |               int number of records           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /                   flow records                /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowFlowDataFormat uint32

func (fdf SFlowFlowDataFormat) decode() (SFlowEnterpriseID, SFlowFlowRecordType) {
	leftField := fdf >> 12
	rightField := uint32(0xFFFFF) & uint32(fdf)
	return SFlowEnterpriseID(leftField), SFlowFlowRecordType(rightField)
}

func (fs SFlowFlowSample) GetRecords() []SFlowRecord {
	return fs.Records
}

func (fs SFlowFlowSample) GetType() SFlowSampleType {
	return SFlowTypeFlowSample
}

func skipFlowRecord(r *bytes.Reader) {
	var rdf SFlowFlowDataFormat
	binary.Read(r, binary.BigEndian, &rdf)
	var recordLength uint32
	binary.Read(r, binary.BigEndian, &recordLength)
	r.Seek(int64(recordLength+((4-recordLength)%4)), 1)
}

func decodeFlowSample(r *bytes.Reader) (SFlowFlowSample, error) {
	s := SFlowFlowSample{}
	var sdf SFlowDataFormat
	var sampleDataSource SFlowDataSource
	binary.Read(r, binary.BigEndian, &sdf)
	s.EnterpriseID, s.Format = sdf.decode()
	binary.Read(r, binary.BigEndian, &s.SampleLength)
	binary.Read(r, binary.BigEndian, &s.SequenceNumber)
	binary.Read(r, binary.BigEndian, &sampleDataSource)
	s.SourceIDClass, s.SourceIDIndex = sampleDataSource.decode()
	binary.Read(r, binary.BigEndian, &s.SamplingRate)
	binary.Read(r, binary.BigEndian, &s.SamplePool)
	binary.Read(r, binary.BigEndian, &s.Dropped)
	binary.Read(r, binary.BigEndian, &s.InputInterface)
	binary.Read(r, binary.BigEndian, &s.OutputInterface)
	binary.Read(r, binary.BigEndian, &s.RecordCount)

	for i := uint32(0); i < s.RecordCount; i++ {
		var rdf SFlowFlowDataFormat
		binary.Read(r, binary.BigEndian, &rdf)
		_, flowRecordType := rdf.decode()
		r.Seek(-4, 1)
		switch flowRecordType {
		case SFlowTypeRawPacketFlow:
			if record, err := decodeRawPacketFlowRecord(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedUserFlow:
			if record, err := decodeExtendedUserFlow(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedUrlFlow:
			if record, err := decodeExtendedURLRecord(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedSwitchFlow:
			if record, err := decodeExtendedSwitchFlowRecord(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedRouterFlow:
			if record, err := decodeExtendedRouterFlowRecord(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedGatewayFlow:
			if record, err := decodeExtendedGatewayFlowRecord(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeEthernetFrameFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeEthernetFrameFlow")
		case SFlowTypeIpv4Flow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeIpv4Flow")
		case SFlowTypeIpv6Flow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeIpv6Flow")
		case SFlowTypeExtendedMlpsFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedMlpsFlow")
		case SFlowTypeExtendedNatFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedNatFlow")
		case SFlowTypeExtendedMlpsTunnelFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedMlpsTunnelFlow")
		case SFlowTypeExtendedMlpsVcFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedMlpsVcFlow")
		case SFlowTypeExtendedMlpsFecFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedMlpsFecFlow")
		case SFlowTypeExtendedMlpsLvpFecFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedMlpsLvpFecFlow")
		case SFlowTypeExtendedVlanFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedVlanFlow")
		default:
			return s, fmt.Errorf("Unsupported flow record type: %d", flowRecordType)

		}

	}

	return s, nil

}

// Counter samples report information about various counter
// objects. Typically these are items like IfInOctets, or
// CPU / Memory stats, etc. SFlow will report these at regular
// intervals as configured on the agent. If one were sufficiently
// industrious, this could be used to replace the typical
// SNMP polling used for such things.
type SFlowCounterSample struct {
	EnterpriseID   SFlowEnterpriseID
	Format         SFlowSampleType
	SampleLength   uint32
	SequenceNumber uint32
	SourceIDClass  SFlowSourceFormat
	SourceIDIndex  SFlowSourceValue
	RecordCount    uint32
	Records        []SFlowRecord
}

// Counter samples have the following structure:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |          int sample sequence number           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |id type |       src id index value             |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |               int number of records           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /                counter records                /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowCounterDataFormat uint32

func (cdf SFlowCounterDataFormat) decode() (SFlowEnterpriseID, SFlowCounterRecordType) {
	leftField := cdf >> 12
	rightField := uint32(0xFFFFF) & uint32(cdf)
	return SFlowEnterpriseID(leftField), SFlowCounterRecordType(rightField)
}

// GetRecords will return a slice of interface types
// representing records. A type switch can be used to
// get at the underlying SFlowCounterRecordType.
func (cs SFlowCounterSample) GetRecords() []SFlowRecord {
	return cs.Records
}

// GetType will report the type of sample. Only the
// compact form of counter samples is supported
func (cs SFlowCounterSample) GetType() SFlowSampleType {
	return SFlowTypeCounterSample
}

type SFlowCounterRecordType uint32

const (
	SFlowTypeGenericInterfaceCounters   SFlowCounterRecordType = 1
	SFlowTypeEthernetInterfaceCounters  SFlowCounterRecordType = 2
	SFlowTypeTokenRingInterfaceCounters SFlowCounterRecordType = 3
	SFlowType100BaseVGInterfaceCounters SFlowCounterRecordType = 4
	SFlowTypeVLANCounters               SFlowCounterRecordType = 5
	SFlowTypeProcessorCounters          SFlowCounterRecordType = 1001
)

func (cr SFlowCounterRecordType) String() string {
	switch cr {
	case SFlowTypeGenericInterfaceCounters:
		return "Generic Interface Counters"
	case SFlowTypeEthernetInterfaceCounters:
		return "Ethernet Interface Counters"
	case SFlowTypeTokenRingInterfaceCounters:
		return "Token Ring Interface Counters"
	case SFlowType100BaseVGInterfaceCounters:
		return "100BaseVG Interface Counters"
	case SFlowTypeVLANCounters:
		return "VLAN Counters"
	case SFlowTypeProcessorCounters:
		return "Processor Counters"
	default:
		return ""

	}
}

func skipCounterRecord(r *bytes.Reader) {
	var cdt uint32
	binary.Read(r, binary.BigEndian, &cdt)
	var rl uint32
	binary.Read(r, binary.BigEndian, &rl)
	r.Seek(int64(rl+((4-rl)%4)), 1)
}

func decodeCounterSample(r *bytes.Reader) (SFlowCounterSample, error) {
	s := SFlowCounterSample{}
	var sdf SFlowDataFormat
	var sampleDataSource SFlowDataSource
	binary.Read(r, binary.BigEndian, &sdf)
	s.EnterpriseID, s.Format = sdf.decode()
	binary.Read(r, binary.BigEndian, &s.SampleLength)
	binary.Read(r, binary.BigEndian, &s.SequenceNumber)
	binary.Read(r, binary.BigEndian, &sampleDataSource)
	s.SourceIDClass, s.SourceIDIndex = sampleDataSource.decode()
	binary.Read(r, binary.BigEndian, &s.RecordCount)

	for i := uint32(0); i < s.RecordCount; i++ {
		var cdf SFlowCounterDataFormat
		binary.Read(r, binary.BigEndian, &cdf)
		_, counterRecordType := cdf.decode()
		r.Seek(-4, 1)
		switch counterRecordType {
		case SFlowTypeGenericInterfaceCounters:
			if record, err := decodeGenericInterfaceCounters(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeEthernetInterfaceCounters:
			if record, err := decodeEthernetCounters(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeTokenRingInterfaceCounters:
			skipCounterRecord(r)
			return s, fmt.Errorf("skipping TypeTokenRingInterfaceCounters")
		case SFlowType100BaseVGInterfaceCounters:
			skipCounterRecord(r)
			return s, fmt.Errorf("skipping Type100BaseVGInterfaceCounters")
		case SFlowTypeVLANCounters:
			skipCounterRecord(r)
			return s, fmt.Errorf("skipping TypeVLANCounters")
		case SFlowTypeProcessorCounters:
			skipCounterRecord(r)
			return s, fmt.Errorf("skipping TypeProcessorCounters")
		default:
			return s, fmt.Errorf("Invalid counter record type: %d", counterRecordType)
		}
	}

	return s, nil

}

// SFlowBaseFlowRecord holds the fields common to all records
// of type SFlowFlowRecordType
type SFlowBaseFlowRecord struct {
	EnterpriseID   SFlowEnterpriseID
	Format         SFlowFlowRecordType
	FlowDataLength uint32
}

func (bfr SFlowBaseFlowRecord) GetType() SFlowFlowRecordType {
	switch bfr.Format {
	case SFlowTypeRawPacketFlow:
		return SFlowTypeRawPacketFlow
	case SFlowTypeEthernetFrameFlow:
		return SFlowTypeEthernetFrameFlow
	case SFlowTypeIpv4Flow:
		return SFlowTypeIpv4Flow
	case SFlowTypeIpv6Flow:
		return SFlowTypeIpv6Flow
	case SFlowTypeExtendedSwitchFlow:
		return SFlowTypeExtendedSwitchFlow
	case SFlowTypeExtendedRouterFlow:
		return SFlowTypeExtendedRouterFlow
	case SFlowTypeExtendedGatewayFlow:
		return SFlowTypeExtendedGatewayFlow
	case SFlowTypeExtendedUserFlow:
		return SFlowTypeExtendedUserFlow
	case SFlowTypeExtendedUrlFlow:
		return SFlowTypeExtendedUrlFlow
	case SFlowTypeExtendedMlpsFlow:
		return SFlowTypeExtendedMlpsFlow
	case SFlowTypeExtendedNatFlow:
		return SFlowTypeExtendedNatFlow
	case SFlowTypeExtendedMlpsTunnelFlow:
		return SFlowTypeExtendedMlpsTunnelFlow
	case SFlowTypeExtendedMlpsVcFlow:
		return SFlowTypeExtendedMlpsVcFlow
	case SFlowTypeExtendedMlpsFecFlow:
		return SFlowTypeExtendedMlpsFecFlow
	case SFlowTypeExtendedMlpsLvpFecFlow:
		return SFlowTypeExtendedMlpsLvpFecFlow
	case SFlowTypeExtendedVlanFlow:
		return SFlowTypeExtendedVlanFlow
	}
	unrecognized := fmt.Sprintln("Unrecognized flow record type:", bfr.Format)
	panic(unrecognized)
}

// SFlowFlowRecordType denotes what kind of Flow Record is
// represented. See RFC 3176
type SFlowFlowRecordType uint32

const (
	SFlowTypeRawPacketFlow          SFlowFlowRecordType = 1
	SFlowTypeEthernetFrameFlow      SFlowFlowRecordType = 2
	SFlowTypeIpv4Flow               SFlowFlowRecordType = 3
	SFlowTypeIpv6Flow               SFlowFlowRecordType = 4
	SFlowTypeExtendedSwitchFlow     SFlowFlowRecordType = 1001
	SFlowTypeExtendedRouterFlow     SFlowFlowRecordType = 1002
	SFlowTypeExtendedGatewayFlow    SFlowFlowRecordType = 1003
	SFlowTypeExtendedUserFlow       SFlowFlowRecordType = 1004
	SFlowTypeExtendedUrlFlow        SFlowFlowRecordType = 1005
	SFlowTypeExtendedMlpsFlow       SFlowFlowRecordType = 1006
	SFlowTypeExtendedNatFlow        SFlowFlowRecordType = 1007
	SFlowTypeExtendedMlpsTunnelFlow SFlowFlowRecordType = 1008
	SFlowTypeExtendedMlpsVcFlow     SFlowFlowRecordType = 1009
	SFlowTypeExtendedMlpsFecFlow    SFlowFlowRecordType = 1010
	SFlowTypeExtendedMlpsLvpFecFlow SFlowFlowRecordType = 1011
	SFlowTypeExtendedVlanFlow       SFlowFlowRecordType = 1012
)

func (rt SFlowFlowRecordType) String() string {
	switch rt {
	case SFlowTypeRawPacketFlow:
		return "Raw Packet Flow Record"
	case SFlowTypeEthernetFrameFlow:
		return "Ethernet Frame Flow Record"
	case SFlowTypeIpv4Flow:
		return "IPv4 Flow Record"
	case SFlowTypeIpv6Flow:
		return "IPv6 Flow Record"
	case SFlowTypeExtendedSwitchFlow:
		return "Extended Switch Flow Record"
	case SFlowTypeExtendedRouterFlow:
		return "Extended Router Flow Record"
	case SFlowTypeExtendedGatewayFlow:
		return "Extended Gateway Flow Record"
	case SFlowTypeExtendedUserFlow:
		return "Extended User Flow Record"
	case SFlowTypeExtendedUrlFlow:
		return "Extended URL Flow Record"
	case SFlowTypeExtendedMlpsFlow:
		return "Extended MPLS Flow Record"
	case SFlowTypeExtendedNatFlow:
		return "Extended NAT Flow Record"
	case SFlowTypeExtendedMlpsTunnelFlow:
		return "Extended MPLS Tunnel Flow Record"
	case SFlowTypeExtendedMlpsVcFlow:
		return "Extended MPLS VC Flow Record"
	case SFlowTypeExtendedMlpsFecFlow:
		return "Extended MPLS FEC Flow Record"
	case SFlowTypeExtendedMlpsLvpFecFlow:
		return "Extended MPLS LVP FEC Flow Record"
	case SFlowTypeExtendedVlanFlow:
		return "Extended VLAN Flow Record"
	default:
		return ""
	}
}

// SFlowRawPacketFlowRecords hold information about a sampled
// packet grabbed as it transited the agent. This is
// perhaps the most useful and interesting record type,
// as it holds the headers of the sampled packet and
// can be used to build up a complete picture of the
// traffic patterns on a network.
//
// The raw packet header is sent back into gopacket for
// decoding, and the resulting gopackt.Packet is stored
// in the Header member
type SFlowRawPacketFlowRecord struct {
	SFlowBaseFlowRecord
	HeaderProtocol uint32
	FrameLength    uint32
	PayloadRemoved uint32
	HeaderLength   uint32
	Header         gopacket.Packet
}

// Raw packet record types have the following structure:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 Header Protocol               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 Frame Length                  |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 Payload Removed               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 Header Length                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  \                     Header                    \
//  \                                               \
//  \                                               \
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

func decodeRawPacketFlowRecord(r *bytes.Reader) (SFlowRawPacketFlowRecord, error) {
	rec := SFlowRawPacketFlowRecord{}

	var fdf SFlowFlowDataFormat
	binary.Read(r, binary.BigEndian, &fdf)
	rec.EnterpriseID, rec.Format = fdf.decode()
	binary.Read(r, binary.BigEndian, &rec.FlowDataLength)

	binary.Read(r, binary.BigEndian, &rec.HeaderProtocol)
	binary.Read(r, binary.BigEndian, &rec.FrameLength)
	binary.Read(r, binary.BigEndian, &rec.PayloadRemoved)
	binary.Read(r, binary.BigEndian, &rec.HeaderLength)
	header := make([]byte, rec.HeaderLength+((4-rec.HeaderLength)%4))
	binary.Read(r, binary.BigEndian, &header)
	rec.Header = gopacket.NewPacket(header, LayerTypeEthernet, gopacket.Default)

	return rec, nil

}

// SFlowExtendedSwitchFlowRecord give additional information
// about the sampled packet if it's available. It's mainly
// useful for getting at the incoming and outgoing VLANs
// An agent may or may not provide this information.
type SFlowExtendedSwitchFlowRecord struct {
	SFlowBaseFlowRecord
	IncomingVLAN         uint32
	IncomingVLANPriority uint32
	OutgoingVLAN         uint32
	OutgoingVLANPriority uint32
}

// Extended switch records have the following structure:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   Incoming VLAN               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                Incoming VLAN Priority         |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   Outgoing VLAN               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                Outgoing VLAN Priority         |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

func decodeExtendedSwitchFlowRecord(r *bytes.Reader) (SFlowExtendedSwitchFlowRecord, error) {
	es := SFlowExtendedSwitchFlowRecord{}
	var fdf SFlowFlowDataFormat
	binary.Read(r, binary.BigEndian, &fdf)
	es.EnterpriseID, es.Format = fdf.decode()
	binary.Read(r, binary.BigEndian, &es.FlowDataLength)
	binary.Read(r, binary.BigEndian, &es.IncomingVLAN)
	binary.Read(r, binary.BigEndian, &es.IncomingVLANPriority)
	binary.Read(r, binary.BigEndian, &es.OutgoingVLAN)
	binary.Read(r, binary.BigEndian, &es.OutgoingVLANPriority)

	return es, nil
}

// SFlowExtendedRouterFlowRecord gives additional information
// about the layer 3 routing information used to forward
// the packet
type SFlowExtendedRouterFlowRecord struct {
	SFlowBaseFlowRecord
	NextHop                net.IP
	NextHopSourceMask      uint32
	NextHopDestinationMask uint32
}

// Extended router records have the following structure:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    Next Hop                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |              Next Hop Source Mask             |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |              Next Hop Destination Mask        |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

func decodeExtendedRouterFlowRecord(r *bytes.Reader) (SFlowExtendedRouterFlowRecord, error) {
	er := SFlowExtendedRouterFlowRecord{}
	var extendedRouterAddressType SFlowIPType
	var fdf SFlowFlowDataFormat

	binary.Read(r, binary.BigEndian, &fdf)
	er.EnterpriseID, er.Format = fdf.decode()
	binary.Read(r, binary.BigEndian, &er.FlowDataLength)
	binary.Read(r, binary.BigEndian, &extendedRouterAddressType)
	er.NextHop = extendedRouterAddressType.decodeIP(r)
	binary.Read(r, binary.BigEndian, &er.NextHopSourceMask)
	binary.Read(r, binary.BigEndian, &er.NextHopDestinationMask)

	return er, nil

}

// SFlowExtendedGatewayFlowRecord describes information treasured by
// nework engineers everywhere: AS path information listing which
// BGP peer sent the packet, and various other BGP related info.
// This information is vital because it gives a picture of how much
// traffic is being sent from / received by various BGP peers.

// Extended gatway records have the following structure:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    Next Hop                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                       AS                      |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  Source AS                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    Peer AS                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  AS Path Count                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /                AS Path / Sequence             /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /                   Communities                 /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    Local Pref                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// AS Path / Sequence:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |     AS Source Type (Path=1 / Sequence=2)      |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |              Path / Sequence length           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /              Path / Sequence Members          /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// Communities:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                communitiy length              |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /              communitiy Members               /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowExtendedGatewayFlowRecord struct {
	SFlowBaseFlowRecord
	NextHop     net.IP
	AS          uint32
	SourceAS    uint32
	PeerAS      uint32
	ASPathCount uint32
	ASPath      []SFlowASDestination
	Communities []uint32
	LocalPref   uint32
}

type SFlowASPathType uint32

const (
	SFlowASSet      SFlowASPathType = 1
	SFlowASSequence SFlowASPathType = 2
)

func (apt SFlowASPathType) String() string {
	switch apt {
	case SFlowASSet:
		return "AS Set"
	case SFlowASSequence:
		return "AS Sequence"
	default:
		return ""
	}
}

type SFlowASDestination struct {
	Type    SFlowASPathType
	Count   uint32
	Members []uint32
}

func (asd SFlowASDestination) String() string {
	switch asd.Type {
	case SFlowASSet:
		return fmt.Sprint("AS Set:", asd.Members)
	case SFlowASSequence:
		return fmt.Sprint("AS Sequence:", asd.Members)
	default:
		return ""
	}
}

func (ad *SFlowASDestination) decodePath(r *bytes.Reader) {

	binary.Read(r, binary.BigEndian, &ad.Type)
	binary.Read(r, binary.BigEndian, &ad.Count)
	ad.Members = make([]uint32, ad.Count)
	binary.Read(r, binary.BigEndian, &ad.Members)

}

func decodeExtendedGatewayFlowRecord(r *bytes.Reader) (SFlowExtendedGatewayFlowRecord, error) {
	eg := SFlowExtendedGatewayFlowRecord{}
	var extendedGatewayAddressType SFlowIPType
	var fdf SFlowFlowDataFormat
	var communitiesLength uint32

	binary.Read(r, binary.BigEndian, &fdf)
	eg.EnterpriseID, eg.Format = fdf.decode()
	binary.Read(r, binary.BigEndian, &eg.FlowDataLength)
	binary.Read(r, binary.BigEndian, &extendedGatewayAddressType)
	eg.NextHop = extendedGatewayAddressType.decodeIP(r)
	binary.Read(r, binary.BigEndian, &eg.AS)
	binary.Read(r, binary.BigEndian, &eg.SourceAS)
	binary.Read(r, binary.BigEndian, &eg.PeerAS)

	binary.Read(r, binary.BigEndian, &eg.ASPathCount)

	for i := uint32(0); i < eg.ASPathCount; i++ {
		asPath := SFlowASDestination{}
		asPath.decodePath(r)
		eg.ASPath = append(eg.ASPath, asPath)
	}

	binary.Read(r, binary.BigEndian, &communitiesLength)
	eg.Communities = make([]uint32, communitiesLength)

	binary.Read(r, binary.BigEndian, &eg.Communities)
	binary.Read(r, binary.BigEndian, &eg.LocalPref)

	return eg, nil
}

// **************************************************
//  Extended URL Flow Record
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   direction                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      URL                      |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      Host                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowURLDirection uint32

const (
	SFlowURLsrc SFlowURLDirection = 1
	SFlowURLdst SFlowURLDirection = 2
)

func (urld SFlowURLDirection) String() string {
	switch urld {
	case SFlowURLsrc:
		return "Source address is the server"
	case SFlowURLdst:
		return "Destination address is the server"
	default:
		return ""
	}
}

type SFlowExtendedURLRecord struct {
	SFlowBaseFlowRecord
	Direction SFlowURLDirection
	URL       string
	Host      string
}

func decodeExtendedURLRecord(r *bytes.Reader) (SFlowExtendedURLRecord, error) {
	eur := SFlowExtendedURLRecord{}
	var fdf SFlowFlowDataFormat
	var urlLen uint32
	var hostLen uint32

	binary.Read(r, binary.BigEndian, &fdf)
	eur.EnterpriseID, eur.Format = fdf.decode()
	binary.Read(r, binary.BigEndian, &eur.FlowDataLength)
	binary.Read(r, binary.BigEndian, &eur.Direction)

	binary.Read(r, binary.BigEndian, &urlLen)
	urlBytes := make([]byte, urlLen+((4-urlLen)%4)) // XDR padding to nearest 4-byte
	binary.Read(r, binary.BigEndian, &urlBytes)
	eur.URL = string(urlBytes[:urlLen])

	binary.Read(r, binary.BigEndian, &hostLen)
	hostBytes := make([]byte, hostLen+((4-hostLen)%4)) // XDR padding to nearest 4-byte
	binary.Read(r, binary.BigEndian, &hostBytes)
	eur.Host = string(hostBytes[:hostLen])

	return eur, nil
}

// **************************************************
//  Extended User Flow Record
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                Source Character Set           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 Source User Id                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |              Destination Character Set        |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |               Destination User ID             |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowExtendedUserFlow struct {
	SFlowBaseFlowRecord
	SourceCharSet      SFlowCharSet
	SourceUserID       string
	DestinationCharSet SFlowCharSet
	DestinationUserID  string
}

type SFlowCharSet uint32

const (
	SFlowCSunknown                 SFlowCharSet = 2
	SFlowCSASCII                   SFlowCharSet = 3
	SFlowCSISOLatin1               SFlowCharSet = 4
	SFlowCSISOLatin2               SFlowCharSet = 5
	SFlowCSISOLatin3               SFlowCharSet = 6
	SFlowCSISOLatin4               SFlowCharSet = 7
	SFlowCSISOLatinCyrillic        SFlowCharSet = 8
	SFlowCSISOLatinArabic          SFlowCharSet = 9
	SFlowCSISOLatinGreek           SFlowCharSet = 10
	SFlowCSISOLatinHebrew          SFlowCharSet = 11
	SFlowCSISOLatin5               SFlowCharSet = 12
	SFlowCSISOLatin6               SFlowCharSet = 13
	SFlowCSISOTextComm             SFlowCharSet = 14
	SFlowCSHalfWidthKatakana       SFlowCharSet = 15
	SFlowCSJISEncoding             SFlowCharSet = 16
	SFlowCSShiftJIS                SFlowCharSet = 17
	SFlowCSEUCPkdFmtJapanese       SFlowCharSet = 18
	SFlowCSEUCFixWidJapanese       SFlowCharSet = 19
	SFlowCSISO4UnitedKingdom       SFlowCharSet = 20
	SFlowCSISO11SwedishForNames    SFlowCharSet = 21
	SFlowCSISO15Italian            SFlowCharSet = 22
	SFlowCSISO17Spanish            SFlowCharSet = 23
	SFlowCSISO21German             SFlowCharSet = 24
	SFlowCSISO60DanishNorwegian    SFlowCharSet = 25
	SFlowCSISO69French             SFlowCharSet = 26
	SFlowCSISO10646UTF1            SFlowCharSet = 27
	SFlowCSISO646basic1983         SFlowCharSet = 28
	SFlowCSINVARIANT               SFlowCharSet = 29
	SFlowCSISO2IntlRefVersion      SFlowCharSet = 30
	SFlowCSNATSSEFI                SFlowCharSet = 31
	SFlowCSNATSSEFIADD             SFlowCharSet = 32
	SFlowCSNATSDANO                SFlowCharSet = 33
	SFlowCSNATSDANOADD             SFlowCharSet = 34
	SFlowCSISO10Swedish            SFlowCharSet = 35
	SFlowCSKSC56011987             SFlowCharSet = 36
	SFlowCSISO2022KR               SFlowCharSet = 37
	SFlowCSEUCKR                   SFlowCharSet = 38
	SFlowCSISO2022JP               SFlowCharSet = 39
	SFlowCSISO2022JP2              SFlowCharSet = 40
	SFlowCSISO13JISC6220jp         SFlowCharSet = 41
	SFlowCSISO14JISC6220ro         SFlowCharSet = 42
	SFlowCSISO16Portuguese         SFlowCharSet = 43
	SFlowCSISO18Greek7Old          SFlowCharSet = 44
	SFlowCSISO19LatinGreek         SFlowCharSet = 45
	SFlowCSISO25French             SFlowCharSet = 46
	SFlowCSISO27LatinGreek1        SFlowCharSet = 47
	SFlowCSISO5427Cyrillic         SFlowCharSet = 48
	SFlowCSISO42JISC62261978       SFlowCharSet = 49
	SFlowCSISO47BSViewdata         SFlowCharSet = 50
	SFlowCSISO49INIS               SFlowCharSet = 51
	SFlowCSISO50INIS8              SFlowCharSet = 52
	SFlowCSISO51INISCyrillic       SFlowCharSet = 53
	SFlowCSISO54271981             SFlowCharSet = 54
	SFlowCSISO5428Greek            SFlowCharSet = 55
	SFlowCSISO57GB1988             SFlowCharSet = 56
	SFlowCSISO58GB231280           SFlowCharSet = 57
	SFlowCSISO61Norwegian2         SFlowCharSet = 58
	SFlowCSISO70VideotexSupp1      SFlowCharSet = 59
	SFlowCSISO84Portuguese2        SFlowCharSet = 60
	SFlowCSISO85Spanish2           SFlowCharSet = 61
	SFlowCSISO86Hungarian          SFlowCharSet = 62
	SFlowCSISO87JISX0208           SFlowCharSet = 63
	SFlowCSISO88Greek7             SFlowCharSet = 64
	SFlowCSISO89ASMO449            SFlowCharSet = 65
	SFlowCSISO90                   SFlowCharSet = 66
	SFlowCSISO91JISC62291984a      SFlowCharSet = 67
	SFlowCSISO92JISC62991984b      SFlowCharSet = 68
	SFlowCSISO93JIS62291984badd    SFlowCharSet = 69
	SFlowCSISO94JIS62291984hand    SFlowCharSet = 70
	SFlowCSISO95JIS62291984handadd SFlowCharSet = 71
	SFlowCSISO96JISC62291984kana   SFlowCharSet = 72
	SFlowCSISO2033                 SFlowCharSet = 73
	SFlowCSISO99NAPLPS             SFlowCharSet = 74
	SFlowCSISO102T617bit           SFlowCharSet = 75
	SFlowCSISO103T618bit           SFlowCharSet = 76
	SFlowCSISO111ECMACyrillic      SFlowCharSet = 77
	SFlowCSa71                     SFlowCharSet = 78
	SFlowCSa72                     SFlowCharSet = 79
	SFlowCSISO123CSAZ24341985gr    SFlowCharSet = 80
	SFlowCSISO88596E               SFlowCharSet = 81
	SFlowCSISO88596I               SFlowCharSet = 82
	SFlowCSISO128T101G2            SFlowCharSet = 83
	SFlowCSISO88598E               SFlowCharSet = 84
	SFlowCSISO88598I               SFlowCharSet = 85
	SFlowCSISO139CSN369103         SFlowCharSet = 86
	SFlowCSISO141JUSIB1002         SFlowCharSet = 87
	SFlowCSISO143IECP271           SFlowCharSet = 88
	SFlowCSISO146Serbian           SFlowCharSet = 89
	SFlowCSISO147Macedonian        SFlowCharSet = 90
	SFlowCSISO150                  SFlowCharSet = 91
	SFlowCSISO151Cuba              SFlowCharSet = 92
	SFlowCSISO6937Add              SFlowCharSet = 93
	SFlowCSISO153GOST1976874       SFlowCharSet = 94
	SFlowCSISO8859Supp             SFlowCharSet = 95
	SFlowCSISO10367Box             SFlowCharSet = 96
	SFlowCSISO158Lap               SFlowCharSet = 97
	SFlowCSISO159JISX02121990      SFlowCharSet = 98
	SFlowCSISO646Danish            SFlowCharSet = 99
	SFlowCSUSDK                    SFlowCharSet = 100
	SFlowCSDKUS                    SFlowCharSet = 101
	SFlowCSKSC5636                 SFlowCharSet = 102
	SFlowCSUnicode11UTF7           SFlowCharSet = 103
	SFlowCSISO2022CN               SFlowCharSet = 104
	SFlowCSISO2022CNEXT            SFlowCharSet = 105
	SFlowCSUTF8                    SFlowCharSet = 106
	SFlowCSISO885913               SFlowCharSet = 109
	SFlowCSISO885914               SFlowCharSet = 110
	SFlowCSISO885915               SFlowCharSet = 111
	SFlowCSISO885916               SFlowCharSet = 112
	SFlowCSGBK                     SFlowCharSet = 113
	SFlowCSGB18030                 SFlowCharSet = 114
	SFlowCSOSDEBCDICDF0415         SFlowCharSet = 115
	SFlowCSOSDEBCDICDF03IRV        SFlowCharSet = 116
	SFlowCSOSDEBCDICDF041          SFlowCharSet = 117
	SFlowCSISO115481               SFlowCharSet = 118
	SFlowCSKZ1048                  SFlowCharSet = 119
	SFlowCSUnicode                 SFlowCharSet = 1000
	SFlowCSUCS4                    SFlowCharSet = 1001
	SFlowCSUnicodeASCII            SFlowCharSet = 1002
	SFlowCSUnicodeLatin1           SFlowCharSet = 1003
	SFlowCSUnicodeJapanese         SFlowCharSet = 1004
	SFlowCSUnicodeIBM1261          SFlowCharSet = 1005
	SFlowCSUnicodeIBM1268          SFlowCharSet = 1006
	SFlowCSUnicodeIBM1276          SFlowCharSet = 1007
	SFlowCSUnicodeIBM1264          SFlowCharSet = 1008
	SFlowCSUnicodeIBM1265          SFlowCharSet = 1009
	SFlowCSUnicode11               SFlowCharSet = 1010
	SFlowCSSCSU                    SFlowCharSet = 1011
	SFlowCSUTF7                    SFlowCharSet = 1012
	SFlowCSUTF16BE                 SFlowCharSet = 1013
	SFlowCSUTF16LE                 SFlowCharSet = 1014
	SFlowCSUTF16                   SFlowCharSet = 1015
	SFlowCSCESU8                   SFlowCharSet = 1016
	SFlowCSUTF32                   SFlowCharSet = 1017
	SFlowCSUTF32BE                 SFlowCharSet = 1018
	SFlowCSUTF32LE                 SFlowCharSet = 1019
	SFlowCSBOCU1                   SFlowCharSet = 1020
	SFlowCSWindows30Latin1         SFlowCharSet = 2000
	SFlowCSWindows31Latin1         SFlowCharSet = 2001
	SFlowCSWindows31Latin2         SFlowCharSet = 2002
	SFlowCSWindows31Latin5         SFlowCharSet = 2003
	SFlowCSHPRoman8                SFlowCharSet = 2004
	SFlowCSAdobeStandardEncoding   SFlowCharSet = 2005
	SFlowCSVenturaUS               SFlowCharSet = 2006
	SFlowCSVenturaInternational    SFlowCharSet = 2007
	SFlowCSDECMCS                  SFlowCharSet = 2008
	SFlowCSPC850Multilingual       SFlowCharSet = 2009
	SFlowCSPCp852                  SFlowCharSet = 2010
	SFlowCSPC8CodePage437          SFlowCharSet = 2011
	SFlowCSPC8DanishNorwegian      SFlowCharSet = 2012
	SFlowCSPC862LatinHebrew        SFlowCharSet = 2013
	SFlowCSPC8Turkish              SFlowCharSet = 2014
	SFlowCSIBMSymbols              SFlowCharSet = 2015
	SFlowCSIBMThai                 SFlowCharSet = 2016
	SFlowCSHPLegal                 SFlowCharSet = 2017
	SFlowCSHPPiFont                SFlowCharSet = 2018
	SFlowCSHPMath8                 SFlowCharSet = 2019
	SFlowCSHPPSMath                SFlowCharSet = 2020
	SFlowCSHPDesktop               SFlowCharSet = 2021
	SFlowCSVenturaMath             SFlowCharSet = 2022
	SFlowCSMicrosoftPublishing     SFlowCharSet = 2023
	SFlowCSWindows31J              SFlowCharSet = 2024
	SFlowCSGB2312                  SFlowCharSet = 2025
	SFlowCSBig5                    SFlowCharSet = 2026
	SFlowCSMacintosh               SFlowCharSet = 2027
	SFlowCSIBM037                  SFlowCharSet = 2028
	SFlowCSIBM038                  SFlowCharSet = 2029
	SFlowCSIBM273                  SFlowCharSet = 2030
	SFlowCSIBM274                  SFlowCharSet = 2031
	SFlowCSIBM275                  SFlowCharSet = 2032
	SFlowCSIBM277                  SFlowCharSet = 2033
	SFlowCSIBM278                  SFlowCharSet = 2034
	SFlowCSIBM280                  SFlowCharSet = 2035
	SFlowCSIBM281                  SFlowCharSet = 2036
	SFlowCSIBM284                  SFlowCharSet = 2037
	SFlowCSIBM285                  SFlowCharSet = 2038
	SFlowCSIBM290                  SFlowCharSet = 2039
	SFlowCSIBM297                  SFlowCharSet = 2040
	SFlowCSIBM420                  SFlowCharSet = 2041
	SFlowCSIBM423                  SFlowCharSet = 2042
	SFlowCSIBM424                  SFlowCharSet = 2043
	SFlowCSIBM500                  SFlowCharSet = 2044
	SFlowCSIBM851                  SFlowCharSet = 2045
	SFlowCSIBM855                  SFlowCharSet = 2046
	SFlowCSIBM857                  SFlowCharSet = 2047
	SFlowCSIBM860                  SFlowCharSet = 2048
	SFlowCSIBM861                  SFlowCharSet = 2049
	SFlowCSIBM863                  SFlowCharSet = 2050
	SFlowCSIBM864                  SFlowCharSet = 2051
	SFlowCSIBM865                  SFlowCharSet = 2052
	SFlowCSIBM868                  SFlowCharSet = 2053
	SFlowCSIBM869                  SFlowCharSet = 2054
	SFlowCSIBM870                  SFlowCharSet = 2055
	SFlowCSIBM871                  SFlowCharSet = 2056
	SFlowCSIBM880                  SFlowCharSet = 2057
	SFlowCSIBM891                  SFlowCharSet = 2058
	SFlowCSIBM903                  SFlowCharSet = 2059
	SFlowCSIBBM904                 SFlowCharSet = 2060
	SFlowCSIBM905                  SFlowCharSet = 2061
	SFlowCSIBM918                  SFlowCharSet = 2062
	SFlowCSIBM1026                 SFlowCharSet = 2063
	SFlowCSIBMEBCDICATDE           SFlowCharSet = 2064
	SFlowCSEBCDICATDEA             SFlowCharSet = 2065
	SFlowCSEBCDICCAFR              SFlowCharSet = 2066
	SFlowCSEBCDICDKNO              SFlowCharSet = 2067
	SFlowCSEBCDICDKNOA             SFlowCharSet = 2068
	SFlowCSEBCDICFISE              SFlowCharSet = 2069
	SFlowCSEBCDICFISEA             SFlowCharSet = 2070
	SFlowCSEBCDICFR                SFlowCharSet = 2071
	SFlowCSEBCDICIT                SFlowCharSet = 2072
	SFlowCSEBCDICPT                SFlowCharSet = 2073
	SFlowCSEBCDICES                SFlowCharSet = 2074
	SFlowCSEBCDICESA               SFlowCharSet = 2075
	SFlowCSEBCDICESS               SFlowCharSet = 2076
	SFlowCSEBCDICUK                SFlowCharSet = 2077
	SFlowCSEBCDICUS                SFlowCharSet = 2078
	SFlowCSUnknown8BiT             SFlowCharSet = 2079
	SFlowCSMnemonic                SFlowCharSet = 2080
	SFlowCSMnem                    SFlowCharSet = 2081
	SFlowCSVISCII                  SFlowCharSet = 2082
	SFlowCSVIQR                    SFlowCharSet = 2083
	SFlowCSKOI8R                   SFlowCharSet = 2084
	SFlowCSHZGB2312                SFlowCharSet = 2085
	SFlowCSIBM866                  SFlowCharSet = 2086
	SFlowCSPC775Baltic             SFlowCharSet = 2087
	SFlowCSKOI8U                   SFlowCharSet = 2088
	SFlowCSIBM00858                SFlowCharSet = 2089
	SFlowCSIBM00924                SFlowCharSet = 2090
	SFlowCSIBM01140                SFlowCharSet = 2091
	SFlowCSIBM01141                SFlowCharSet = 2092
	SFlowCSIBM01142                SFlowCharSet = 2093
	SFlowCSIBM01143                SFlowCharSet = 2094
	SFlowCSIBM01144                SFlowCharSet = 2095
	SFlowCSIBM01145                SFlowCharSet = 2096
	SFlowCSIBM01146                SFlowCharSet = 2097
	SFlowCSIBM01147                SFlowCharSet = 2098
	SFlowCSIBM01148                SFlowCharSet = 2099
	SFlowCSIBM01149                SFlowCharSet = 2100
	SFlowCSBig5HKSCS               SFlowCharSet = 2101
	SFlowCSIBM1047                 SFlowCharSet = 2102
	SFlowCSPTCP154                 SFlowCharSet = 2103
	SFlowCSAmiga1251               SFlowCharSet = 2104
	SFlowCSKOI7switched            SFlowCharSet = 2105
	SFlowCSBRF                     SFlowCharSet = 2106
	SFlowCSTSCII                   SFlowCharSet = 2107
	SFlowCSCP51932                 SFlowCharSet = 2108
	SFlowCSwindows874              SFlowCharSet = 2109
	SFlowCSwindows1250             SFlowCharSet = 2250
	SFlowCSwindows1251             SFlowCharSet = 2251
	SFlowCSwindows1252             SFlowCharSet = 2252
	SFlowCSwindows1253             SFlowCharSet = 2253
	SFlowCSwindows1254             SFlowCharSet = 2254
	SFlowCSwindows1255             SFlowCharSet = 2255
	SFlowCSwindows1256             SFlowCharSet = 2256
	SFlowCSwindows1257             SFlowCharSet = 2257
	SFlowCSwindows1258             SFlowCharSet = 2258
	SFlowCSTIS620                  SFlowCharSet = 2259
	SFlowCS50220                   SFlowCharSet = 2260
	SFlowCSreserved                SFlowCharSet = 3000
)

func decodeExtendedUserFlow(r *bytes.Reader) (SFlowExtendedUserFlow, error) {
	eu := SFlowExtendedUserFlow{}
	var fdf SFlowFlowDataFormat
	var srcUserLen uint32
	var dstUserLen uint32

	binary.Read(r, binary.BigEndian, &fdf)
	eu.EnterpriseID, eu.Format = fdf.decode()
	binary.Read(r, binary.BigEndian, &eu.FlowDataLength)

	binary.Read(r, binary.BigEndian, &eu.SourceCharSet)

	binary.Read(r, binary.BigEndian, &srcUserLen)
	srcUserBytes := make([]byte, srcUserLen+((4-srcUserLen)%4)) // XDR padding to nearest 4-byte
	binary.Read(r, binary.BigEndian, &srcUserBytes)
	eu.SourceUserID = string(srcUserBytes[:srcUserLen])

	binary.Read(r, binary.BigEndian, &eu.DestinationCharSet)

	binary.Read(r, binary.BigEndian, &dstUserLen)
	dstUserBytes := make([]byte, dstUserLen+((4-dstUserLen)%4)) // XDR padding to nearest 4-byte
	binary.Read(r, binary.BigEndian, &dstUserBytes)
	eu.DestinationUserID = string(dstUserBytes[:dstUserLen])

	return eu, nil

}

// **************************************************
//  Counter Record
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  counter length               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /                   counter data                /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowBaseCounterRecord struct {
	EnterpriseID   SFlowEnterpriseID
	Format         SFlowCounterRecordType
	FlowDataLength uint32
}

func (bcr SFlowBaseCounterRecord) GetType() SFlowCounterRecordType {
	switch bcr.Format {
	case SFlowTypeGenericInterfaceCounters:
		return SFlowTypeGenericInterfaceCounters
	case SFlowTypeEthernetInterfaceCounters:
		return SFlowTypeEthernetInterfaceCounters
	case SFlowTypeTokenRingInterfaceCounters:
		return SFlowTypeTokenRingInterfaceCounters
	case SFlowType100BaseVGInterfaceCounters:
		return SFlowType100BaseVGInterfaceCounters
	case SFlowTypeVLANCounters:
		return SFlowTypeVLANCounters
	case SFlowTypeProcessorCounters:
		return SFlowTypeProcessorCounters

	}
	unrecognized := fmt.Sprint("Unrecognized counter record type:", bcr.Format)
	panic(unrecognized)
}

// **************************************************
//  Counter Record
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  counter length               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    IfIndex                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    IfType                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IfSpeed                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IfDirection                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    IfStatus                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IFInOctets                  |
//  |                                               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IfInUcastPkts               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  IfInMulticastPkts            |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  IfInBroadcastPkts            |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    IfInDiscards               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    InInErrors                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  IfInUnknownProtos            |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IfOutOctets                 |
//  |                                               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IfOutUcastPkts              |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  IfOutMulticastPkts           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  IfOutBroadcastPkts           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IfOutDiscards               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    IfOUtErrors                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 IfPromiscouousMode            |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowGenericInterfaceCounters struct {
	SFlowBaseCounterRecord
	IfIndex     uint32
	IfType      uint32
	IfSpeed     uint64
	IfDirection uint32

	IfStatus uint32

	IfInOctets         uint64
	IfInUcastPkts      uint32
	IfInMulticastPkts  uint32
	IfInBroadcastPkts  uint32
	IfInDiscards       uint32
	IfInErrors         uint32
	IfInUnknownProtos  uint32
	IfOutOctets        uint64
	IfOutUcastPkts     uint32
	IfOutMulticastPkts uint32
	IfOutBroadcastPkts uint32
	IfOutDiscards      uint32
	IfOutErrors        uint32
	IfPromiscuousMode  uint32
}

func decodeGenericInterfaceCounters(r *bytes.Reader) (SFlowGenericInterfaceCounters, error) {
	gic := SFlowGenericInterfaceCounters{}
	var cdf SFlowCounterDataFormat

	binary.Read(r, binary.BigEndian, &cdf)
	gic.EnterpriseID, gic.Format = cdf.decode()
	binary.Read(r, binary.BigEndian, &gic.FlowDataLength)

	binary.Read(r, binary.BigEndian, &gic.IfIndex)
	binary.Read(r, binary.BigEndian, &gic.IfType)
	binary.Read(r, binary.BigEndian, &gic.IfSpeed)
	binary.Read(r, binary.BigEndian, &gic.IfDirection)
	binary.Read(r, binary.BigEndian, &gic.IfStatus)

	binary.Read(r, binary.BigEndian, &gic.IfInOctets)
	binary.Read(r, binary.BigEndian, &gic.IfInUcastPkts)
	binary.Read(r, binary.BigEndian, &gic.IfInMulticastPkts)
	binary.Read(r, binary.BigEndian, &gic.IfInBroadcastPkts)
	binary.Read(r, binary.BigEndian, &gic.IfInDiscards)
	binary.Read(r, binary.BigEndian, &gic.IfInErrors)
	binary.Read(r, binary.BigEndian, &gic.IfInUnknownProtos)

	binary.Read(r, binary.BigEndian, &gic.IfOutOctets)
	binary.Read(r, binary.BigEndian, &gic.IfOutUcastPkts)
	binary.Read(r, binary.BigEndian, &gic.IfOutMulticastPkts)
	binary.Read(r, binary.BigEndian, &gic.IfOutBroadcastPkts)
	binary.Read(r, binary.BigEndian, &gic.IfOutDiscards)
	binary.Read(r, binary.BigEndian, &gic.IfOutErrors)

	binary.Read(r, binary.BigEndian, &gic.IfPromiscuousMode)
	return gic, nil
}

// **************************************************
//  Counter Record
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  counter length               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /                   counter data                /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowEthernetCounters struct {
	SFlowBaseCounterRecord

	Dot3StatsAlignmentErrors           uint32
	Dot3StatsFCSErrors                 uint32
	Dot3StatsSingleCollisionFrames     uint32
	Dot3StatsMultipleCollisionFrames   uint32
	Dot3StatsSQETestErrors             uint32
	Dot3StatsDeferredTransmissions     uint32
	Dot3StatsLateCollisions            uint32
	Dot3StatsExcessiveCollisions       uint32
	Dot3StatsInternalMacTransmitErrors uint32
	Dot3StatsCarrierSenseErrors        uint32
	Dot3StatsFrameTooLongs             uint32
	Dot3StatsInternalMacReceiveErrors  uint32
	Dot3StatsSymbolErrors              uint32
}

func decodeEthernetCounters(r *bytes.Reader) (SFlowEthernetCounters, error) {
	ec := SFlowEthernetCounters{}
	var cdf SFlowCounterDataFormat

	binary.Read(r, binary.BigEndian, &cdf)
	ec.EnterpriseID, ec.Format = cdf.decode()
	binary.Read(r, binary.BigEndian, &ec.FlowDataLength)

	binary.Read(r, binary.BigEndian, &ec.Dot3StatsAlignmentErrors)
	binary.Read(r, binary.BigEndian, &ec.Dot3StatsFCSErrors)
	binary.Read(r, binary.BigEndian, &ec.Dot3StatsSingleCollisionFrames)
	binary.Read(r, binary.BigEndian, &ec.Dot3StatsMultipleCollisionFrames)
	binary.Read(r, binary.BigEndian, &ec.Dot3StatsSQETestErrors)
	binary.Read(r, binary.BigEndian, &ec.Dot3StatsDeferredTransmissions)
	binary.Read(r, binary.BigEndian, &ec.Dot3StatsLateCollisions)
	binary.Read(r, binary.BigEndian, &ec.Dot3StatsExcessiveCollisions)
	binary.Read(r, binary.BigEndian, &ec.Dot3StatsInternalMacTransmitErrors)
	binary.Read(r, binary.BigEndian, &ec.Dot3StatsCarrierSenseErrors)
	binary.Read(r, binary.BigEndian, &ec.Dot3StatsFrameTooLongs)
	binary.Read(r, binary.BigEndian, &ec.Dot3StatsInternalMacReceiveErrors)
	binary.Read(r, binary.BigEndian, &ec.Dot3StatsSymbolErrors)

	return ec, nil

}
