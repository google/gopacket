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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"code.google.com/p/gopacket"
)

// Sample is a container that holds at least one record, plus metadata
// about the sample(s). Samples can be of two general types: flow samples
// and counter samples. (There are 'extended' versions of both of these
// but this decoder does not support them because I couldn't get any example
// data to test with.)
type Sample interface {
	GetRecords() []Record
	String() string
	GetType() SampleType
}

// Record holds both flow sample records and counter sample records.
// A Record is the structure that actually holds the sampled data
// and / or counters.
type Record interface {
	String() string
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
	TypeSingleInterface      SFlowSourceFormat = 0
	TypePacketDiscarded      SFlowSourceFormat = 1
	TypeMultipleDestinations SFlowSourceFormat = 2
)

func (sdf SFlowSourceFormat) String() string {
	switch sdf {
	case TypeSingleInterface:
		return "Single Interface"
	case TypePacketDiscarded:
		return "Packet Discarded"
	case TypeMultipleDestinations:
		return "Multiple Destinations"
	}
	return ""
}

func decodeSFlow(data []byte, p gopacket.PacketBuilder) error {
	s := &SFlow{}
	err := s.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(s)
	p.SetApplicationLayer(s)
	return nil
}

// SFlow is the outermost container which holds some basic information
// about the reporting agent, and holds at least one sample record
type SFlow struct {
	BaseLayer

	DatagramVersion uint32
	AgentAddress    net.IP
	SubAgentID      uint32
	SequenceNumber  uint32
	AgentUptime     uint32
	SampleCount     uint32
	Samples         []Sample
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

// SampleFlowDataFormat encodes the EnterpriseID in the most
// significant 12 bits, and the SampleType in the least significant
// 20 bits.
type SampleFlowDataFormat uint32

func (sdf SampleFlowDataFormat) decode() (EnterpriseID, SampleType) {
	leftField := sdf >> 12
	rightField := uint32(0xFFFFF) & uint32(sdf)
	return EnterpriseID(leftField), SampleType(rightField)
}

// EnterpriseID is used to differentiate between the
// official SFlow standard, and other, vendor-specific
// types of flow data. (Similiar to SNMP's enterprise MIB
// OIDs) Only the office SFlow Enterprise ID is decoded
// here.
type EnterpriseID uint32

const (
	TypeSFlowStandard EnterpriseID = 0
)

func (eid EnterpriseID) String() string {
	switch eid {
	case TypeSFlowStandard:
		return "Standard SFlow"
	}
	return ""
}

func (eid EnterpriseID) GetType() EnterpriseID {
	return TypeSFlowStandard
}

// SampleType specifies the type of sample. Only flow samples
// and counter samples are supported
type SampleType uint32

const (
	TypeFlowSample            SampleType = 1
	TypeCounterSample         SampleType = 2
	TypeExpandedFlowSample    SampleType = 3
	TypeExpandedCounterSample SampleType = 4
)

func (st SampleType) GetType() SampleType {
	switch st {
	case TypeFlowSample:
		return TypeFlowSample
	case TypeCounterSample:
		return TypeCounterSample
	case TypeExpandedFlowSample:
		return TypeExpandedFlowSample
	case TypeExpandedCounterSample:
		return TypeExpandedCounterSample
	default:
		panic("Invalid Sample Type")
	}
}

func (st SampleType) String() string {
	switch st {
	case TypeFlowSample:
		return "Flow Sample"
	case TypeCounterSample:
		return "Counter Sample"
	case TypeExpandedFlowSample:
		return "Expanded Flow Sample"
	case TypeExpandedCounterSample:
		return "Expanded Counter Sample"
	}

	return ""
}

func (s *SFlow) LayerType() gopacket.LayerType { return LayerTypeSFlow }

func (d *SFlow) Payload() []byte { return nil }

func (d *SFlow) CanDecode() gopacket.LayerClass { return LayerTypeSFlow }

func (d *SFlow) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

func (sf SFlow) String() string {
	var out string
	out = fmt.Sprintf("%16s: %d\n", "Datagram Version", sf.DatagramVersion)
	out += fmt.Sprintf("%16s: %s\n", "Agent Address", sf.AgentAddress)
	out += fmt.Sprintf("%16s: %d\n", "Sub-Agnet ID", sf.SubAgentID)
	out += fmt.Sprintf("%16s: %d\n", "Sequence Number", sf.SequenceNumber)
	out += fmt.Sprintf("%16s: %d\n", "Agent Uptime", sf.AgentUptime)
	out += fmt.Sprintf("%16s: %d\n", "Sample Count", sf.SampleCount)
	out += fmt.Sprint("\n")

	for i, sample := range sf.Samples {
		out += fmt.Sprintf("%16s #%d:\n\n", "Sample", (i + 1))
		out += sample.String()
	}

	return out
}

// SFlowIPType determines what form the IP address being decoded will
// take. This is an XDR union type allowing for both IPv4 and IPv6
type SFlowIPType uint32

const (
	TypeIPv4 SFlowIPType = 1
	TypeIPv6 SFlowIPType = 2
)

func (s SFlowIPType) String() string {
	switch s {
	case TypeIPv4:
		return "IPv4"
	case TypeIPv6:
		return "IPv6"
	}
	return ""
}

func (s SFlowIPType) decodeIP(r io.Reader) net.IP {
	var length int
	switch SFlowIPType(s) {
	case TypeIPv4:
		length = 4
	case TypeIPv6:
		length = 16
	default:
		length = 0
	}

	buff := make([]byte, length)
	if length != 0 {
		r.Read(buff)
	}

	return buff

}

func (s *SFlow) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

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
		var sdf SampleFlowDataFormat
		binary.Read(r, binary.BigEndian, &sdf)
		_, sampleType := sdf.decode()
		r.Seek(-4, 1)

		switch sampleType {
		case TypeFlowSample:
			if flowSample, err := decodeFlowSample(r); err == nil {
				s.Samples = append(s.Samples, flowSample)
			} else {
				return err
			}
		case TypeCounterSample:
			if counterSample, err := decodeCounterSample(r); err == nil {
				s.Samples = append(s.Samples, counterSample)
			} else {
				return err
			}

		case TypeExpandedFlowSample:
			// TODO
			return fmt.Errorf("Unsupported SFlow sample type TypeExpandedFlowSample")
		case TypeExpandedCounterSample:
			// TODO
			return fmt.Errorf("Unsupported SFlow sample type TypeExpandedCounterSample")
		default:
			return fmt.Errorf("Unsupported SFlow sample type %d", sampleType)
		}

	}

	return nil

}

// FlowSample represents a sampled packet and contains
// one or more records describing the packet
type FlowSample struct {
	EnterpriseID    EnterpriseID
	Format          SampleType
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
	Records         []Record
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

type FlowDataFormat uint32

func (fdf FlowDataFormat) decode() (EnterpriseID, FlowRecordType) {
	leftField := fdf >> 12
	rightField := uint32(0xFFFFF) & uint32(fdf)
	return EnterpriseID(leftField), FlowRecordType(rightField)
}

func (fs FlowSample) GetRecords() []Record {
	return fs.Records
}

func (fs FlowSample) GetType() SampleType {
	return TypeFlowSample
}

func (fs FlowSample) String() string {
	var out string
	//out = fmt.Sprintf("%24s\n\n", fs.GetType())
	out += fmt.Sprintf("%24s: %s\n", "Enterprise ID", fs.EnterpriseID)
	out += fmt.Sprintf("%24s: %s\n", "Format", fs.Format)
	out += fmt.Sprintf("%24s: %d\n", "Sample Length", fs.SampleLength)
	out += fmt.Sprintf("%24s: %d\n", "Sequence Number", fs.SequenceNumber)
	out += fmt.Sprintf("%24s: %d\n", "Source ID Class", fs.SourceIDClass)
	out += fmt.Sprintf("%24s: %d\n", "Source ID Index", fs.SourceIDIndex)
	out += fmt.Sprintf("%24s: %d\n", "Sampling Rate", fs.SamplingRate)
	out += fmt.Sprintf("%24s: %d\n", "Sample Pool", fs.SamplePool)
	out += fmt.Sprintf("%24s: %d\n", "Dropped", fs.Dropped)
	out += fmt.Sprintf("%24s: %d\n", "Input Interface", fs.InputInterface)
	out += fmt.Sprintf("%24s: %d\n", "Output Interface", fs.OutputInterface)
	out += fmt.Sprintf("%24s: %d\n", "Record Count", fs.RecordCount)
	out += fmt.Sprint("\n")

	for i, record := range fs.Records {
		out += fmt.Sprintf("%24s #%d:\n\n", "Record", (i + 1))
		out += record.String()
	}

	return out
}

func skipFlowRecord(r *bytes.Reader) {
	var rdf FlowDataFormat
	binary.Read(r, binary.BigEndian, &rdf)
	var recordLength uint32
	binary.Read(r, binary.BigEndian, &recordLength)
	r.Seek(int64(recordLength+((4-recordLength)%4)), 1)
}

func decodeFlowSample(r *bytes.Reader) (FlowSample, error) {
	s := FlowSample{}
	var sdf SampleFlowDataFormat
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
		var rdf FlowDataFormat
		binary.Read(r, binary.BigEndian, &rdf)
		_, FlowRecordType := rdf.decode()
		r.Seek(-4, 1)
		switch FlowRecordType {
		case TypeRawPacketFlow:
			if record, err := decodeRawPacketFlowRecord(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case TypeExtendedUserFlow:
			if record, err := decodeExtendedUserFlow(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case TypeExtendedUrlFlow:
			if record, err := decodeExtendedURLRecord(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case TypeExtendedSwitchFlow:
			if record, err := decodeExtendedSwitchFlowRecord(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case TypeExtendedRouterFlow:
			if record, err := decodeExtendedRouterFlowRecord(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case TypeExtendedGatewayFlow:
			if record, err := decodeExtendedGatewayFlowRecord(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case TypeEthernetFrameFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeEthernetFrameFlow")
		case TypeIpv4Flow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeIpv4Flow")
		case TypeIpv6Flow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeIpv6Flow")
		case TypeExtendedMlpsFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedMlpsFlow")
		case TypeExtendedNatFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedNatFlow")
		case TypeExtendedMlpsTunnelFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedMlpsTunnelFlow")
		case TypeExtendedMlpsVcFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedMlpsVcFlow")
		case TypeExtendedMlpsFecFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedMlpsFecFlow")
		case TypeExtendedMlpsLvpFecFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedMlpsLvpFecFlow")
		case TypeExtendedVlanFlow:
			// TODO
			skipFlowRecord(r)
			return s, fmt.Errorf("skipping TypeExtendedVlanFlow")
		default:
			return s, fmt.Errorf("Unsupported flow record type: %d", FlowRecordType)

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
type CounterSample struct {
	EnterpriseID   EnterpriseID
	Format         SampleType
	SampleLength   uint32
	SequenceNumber uint32
	SourceIDClass  SFlowSourceFormat
	SourceIDIndex  SFlowSourceValue
	RecordCount    uint32
	Records        []Record
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

type CounterDataFormat uint32

func (cdf CounterDataFormat) decode() (EnterpriseID, CounterRecordType) {
	leftField := cdf >> 12
	rightField := uint32(0xFFFFF) & uint32(cdf)
	return EnterpriseID(leftField), CounterRecordType(rightField)
}

func (cs CounterSample) String() string {
	var out string
	out = fmt.Sprintf("%24s\n\n", cs.GetType())
	out += fmt.Sprintf("%24s: %s\n", "Enterprise ID", cs.EnterpriseID)
	out += fmt.Sprintf("%24s: %s\n", "Format", cs.Format)
	out += fmt.Sprintf("%24s: %d\n", "Sample Length", cs.SampleLength)
	out += fmt.Sprintf("%24s: %d\n", "Sequence Number", cs.SequenceNumber)
	out += fmt.Sprintf("%24s: %d\n", "Source ID Class", cs.SourceIDClass)
	out += fmt.Sprintf("%24s: %d\n", "Source ID Index", cs.SourceIDIndex)
	out += fmt.Sprintf("%24s: %d\n", "Record Count", cs.RecordCount)
	out += fmt.Sprint("\n")

	for i, record := range cs.Records {
		out += fmt.Sprintf("%24s #%d:\n\n", "Record", (i + 1))
		out += record.String()
	}

	return out
}

// GetRecords will return a slice of interface types
// representing records. A type switch can be used to
// get at the underlying CounterRecordType.
func (cs CounterSample) GetRecords() []Record {
	return cs.Records
}

// GetType will report the type of sample. Only the
// compact form of counter samples is supported
func (cs CounterSample) GetType() SampleType {
	return TypeCounterSample
}

type CounterRecordType uint32

const (
	TypeGenericInterfaceCounters   CounterRecordType = 1
	TypeEthernetInterfaceCounters  CounterRecordType = 2
	TypeTokenRingInterfaceCounters CounterRecordType = 3
	Type100BaseVGInterfaceCounters CounterRecordType = 4
	TypeVLANCounters               CounterRecordType = 5
	TypeProcessorCounters          CounterRecordType = 1001
)

func (cr CounterRecordType) String() string {
	switch cr {
	case TypeGenericInterfaceCounters:
		return "Generic Interface Counters"
	case TypeEthernetInterfaceCounters:
		return "Ethernet Interface Counters"
	case TypeTokenRingInterfaceCounters:
		return "Token Ring Interface Counters"
	case Type100BaseVGInterfaceCounters:
		return "100BaseVG Interface Counters"
	case TypeVLANCounters:
		return "VLAN Counters"
	case TypeProcessorCounters:
		return "Processor Counters"

	}
	return ""
}

func skipCounterRecord(r *bytes.Reader) {
	var cdt uint32
	binary.Read(r, binary.BigEndian, &cdt)
	var rl uint32
	binary.Read(r, binary.BigEndian, &rl)
	r.Seek(int64(rl+((4-rl)%4)), 1)
}

func decodeCounterSample(r *bytes.Reader) (CounterSample, error) {
	s := CounterSample{}
	var sdf SampleFlowDataFormat
	var sampleDataSource SFlowDataSource
	binary.Read(r, binary.BigEndian, &sdf)
	s.EnterpriseID, s.Format = sdf.decode()
	binary.Read(r, binary.BigEndian, &s.SampleLength)
	binary.Read(r, binary.BigEndian, &s.SequenceNumber)
	binary.Read(r, binary.BigEndian, &sampleDataSource)
	s.SourceIDClass, s.SourceIDIndex = sampleDataSource.decode()
	binary.Read(r, binary.BigEndian, &s.RecordCount)

	for i := uint32(0); i < s.RecordCount; i++ {
		var cdf CounterDataFormat
		binary.Read(r, binary.BigEndian, &cdf)
		_, CounterRecordType := cdf.decode()
		r.Seek(-4, 1)
		switch CounterRecordType {
		case TypeGenericInterfaceCounters:
			if record, err := decodeGenericInterfaceCounters(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case TypeEthernetInterfaceCounters:
			if record, err := decodeEthernetCounters(r); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case TypeTokenRingInterfaceCounters:
			skipCounterRecord(r)
			return s, fmt.Errorf("skipping TypeTokenRingInterfaceCounters")
		case Type100BaseVGInterfaceCounters:
			skipCounterRecord(r)
			return s, fmt.Errorf("skipping Type100BaseVGInterfaceCounters")
		case TypeVLANCounters:
			skipCounterRecord(r)
			return s, fmt.Errorf("skipping TypeVLANCounters")
		case TypeProcessorCounters:
			skipCounterRecord(r)
			return s, fmt.Errorf("skipping TypeProcessorCounters")
		default:
			return s, fmt.Errorf("Invalid counter record type: %d", CounterRecordType)
		}
	}

	return s, nil

}

// BaseFlowRecord holds the fields common to all records
// of type FlowReordType
type BaseFlowRecord struct {
	EnterpriseID   EnterpriseID
	Format         FlowRecordType
	FlowDataLength uint32
}

func (bfr BaseFlowRecord) GetType() FlowRecordType {
	switch bfr.Format {
	case TypeRawPacketFlow:
		return TypeRawPacketFlow
	case TypeEthernetFrameFlow:
		return TypeEthernetFrameFlow
	case TypeIpv4Flow:
		return TypeIpv4Flow
	case TypeIpv6Flow:
		return TypeIpv6Flow
	case TypeExtendedSwitchFlow:
		return TypeExtendedSwitchFlow
	case TypeExtendedRouterFlow:
		return TypeExtendedRouterFlow
	case TypeExtendedGatewayFlow:
		return TypeExtendedGatewayFlow
	case TypeExtendedUserFlow:
		return TypeExtendedUserFlow
	case TypeExtendedUrlFlow:
		return TypeExtendedUrlFlow
	case TypeExtendedMlpsFlow:
		return TypeExtendedMlpsFlow
	case TypeExtendedNatFlow:
		return TypeExtendedNatFlow
	case TypeExtendedMlpsTunnelFlow:
		return TypeExtendedMlpsTunnelFlow
	case TypeExtendedMlpsVcFlow:
		return TypeExtendedMlpsVcFlow
	case TypeExtendedMlpsFecFlow:
		return TypeExtendedMlpsFecFlow
	case TypeExtendedMlpsLvpFecFlow:
		return TypeExtendedMlpsLvpFecFlow
	case TypeExtendedVlanFlow:
		return TypeExtendedVlanFlow
	}
	unrecognized := fmt.Sprintln("Unrecognized flow record type:", bfr.Format)
	panic(unrecognized)
}

// FlowRecordType denotes what kind of Flow Record is
// represented. See RFC 3176
type FlowRecordType uint32

const (
	TypeRawPacketFlow          FlowRecordType = 1
	TypeEthernetFrameFlow      FlowRecordType = 2
	TypeIpv4Flow               FlowRecordType = 3
	TypeIpv6Flow               FlowRecordType = 4
	TypeExtendedSwitchFlow     FlowRecordType = 1001
	TypeExtendedRouterFlow     FlowRecordType = 1002
	TypeExtendedGatewayFlow    FlowRecordType = 1003
	TypeExtendedUserFlow       FlowRecordType = 1004
	TypeExtendedUrlFlow        FlowRecordType = 1005
	TypeExtendedMlpsFlow       FlowRecordType = 1006
	TypeExtendedNatFlow        FlowRecordType = 1007
	TypeExtendedMlpsTunnelFlow FlowRecordType = 1008
	TypeExtendedMlpsVcFlow     FlowRecordType = 1009
	TypeExtendedMlpsFecFlow    FlowRecordType = 1010
	TypeExtendedMlpsLvpFecFlow FlowRecordType = 1011
	TypeExtendedVlanFlow       FlowRecordType = 1012
)

func (rt FlowRecordType) String() string {
	switch rt {
	case TypeRawPacketFlow:
		return "Raw Packet Flow Record"
	case TypeEthernetFrameFlow:
		return "Ethernet Frame Flow Record"
	case TypeIpv4Flow:
		return "IPv4 Flow Record"
	case TypeIpv6Flow:
		return "IPv6 Flow Record"
	case TypeExtendedSwitchFlow:
		return "Extended Switch Flow Record"
	case TypeExtendedRouterFlow:
		return "Extended Router Flow Record"
	case TypeExtendedGatewayFlow:
		return "Extended Gateway Flow Record"
	case TypeExtendedUserFlow:
		return "Extended User Flow Record"
	case TypeExtendedUrlFlow:
		return "Extended URL Flow Record"
	case TypeExtendedMlpsFlow:
		return "Extended MPLS Flow Record"
	case TypeExtendedNatFlow:
		return "Extended NAT Flow Record"
	case TypeExtendedMlpsTunnelFlow:
		return "Extended MPLS Tunnel Flow Record"
	case TypeExtendedMlpsVcFlow:
		return "Extended MPLS VC Flow Record"
	case TypeExtendedMlpsFecFlow:
		return "Extended MPLS FEC Flow Record"
	case TypeExtendedMlpsLvpFecFlow:
		return "Extended MPLS LVP FEC Flow Record"
	case TypeExtendedVlanFlow:
		return "Extended VLAN Flow Record"
	}
	return ""
}

// RawPacketFlowRecords hold information about a sampled
// packet grabbed as it transited the agent. This is
// perhaps the most useful and interesting record type,
// as it holds the headers of the sampled packet and
// can be used to build up a complete picture of the
// traffic patterns on a network.
//
// The raw packet header is sent back into gopacket for
// decoding, and the resulting gopackt.Packet is stored
// in the Header member
type RawPacketFlowRecord struct {
	BaseFlowRecord
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

func (fr RawPacketFlowRecord) String() string {
	var out string
	out = fmt.Sprintf("%32s\n\n", fr.GetType())
	out += fmt.Sprintf("%32s: %s\n", "Enterprise ID", fr.EnterpriseID)
	out += fmt.Sprintf("%32s: %s\n", "Format", fr.Format)
	out += fmt.Sprintf("%32s: %d\n", "Flow Data Length", fr.FlowDataLength)
	out += fmt.Sprintf("%32s: %d\n", "Header Protocol", fr.HeaderProtocol)
	out += fmt.Sprintf("%32s: %d\n", "Frame Length:", fr.FrameLength)
	out += fmt.Sprintf("%32s: %d\n", "Payload Removed", fr.PayloadRemoved)
	out += fmt.Sprintf("%32s: %d\n", "Header Length", fr.HeaderLength)
	out += fmt.Sprintf("%32s:\n\n", "Sampled Packet Flow Summary")
	out += fmt.Sprintf("%32s%-64s\n", "", fr.Header.LinkLayer().LinkFlow())
	out += fmt.Sprintf("%32s%-64s\n", "", fr.Header.NetworkLayer().NetworkFlow())
	out += fmt.Sprintf("%32s%-64s\n", "", fr.Header.TransportLayer().TransportFlow())

	out += fmt.Sprint("\n")

	return out

}

func decodeRawPacketFlowRecord(r *bytes.Reader) (RawPacketFlowRecord, error) {
	rec := RawPacketFlowRecord{}

	var fdf FlowDataFormat
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

// ExtendedSwitchFlowRecord give additional information
// about the sampled packet if it's available. It's mainly
// useful for getting at the incoming and outgoing VLANs
// An agent may or may not provide this information.
type ExtendedSwitchFlowRecord struct {
	BaseFlowRecord
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

func (es ExtendedSwitchFlowRecord) String() string {
	var out string
	out = fmt.Sprintf("%32s\n\n", es.GetType())
	out += fmt.Sprintf("%32s: %s\n", "Enterprise ID", es.EnterpriseID)
	out += fmt.Sprintf("%32s: %s\n", "Format", es.Format)
	out += fmt.Sprintf("%32s: %d\n", "Flow Data Length", es.FlowDataLength)
	out += fmt.Sprintf("%32s: %d\n", "Incoming VLAN", es.IncomingVLAN)
	out += fmt.Sprintf("%32s: %d\n", "Incoming VLAN Priority", es.IncomingVLANPriority)
	out += fmt.Sprintf("%32s: %d\n", "Outgoing VLAN", es.OutgoingVLAN)
	out += fmt.Sprintf("%32s: %d\n", "Outgoing VLAN Priority", es.OutgoingVLANPriority)
	out += fmt.Sprint("\n")

	return out
}

func decodeExtendedSwitchFlowRecord(r *bytes.Reader) (ExtendedSwitchFlowRecord, error) {
	es := ExtendedSwitchFlowRecord{}
	var fdf FlowDataFormat
	binary.Read(r, binary.BigEndian, &fdf)
	es.EnterpriseID, es.Format = fdf.decode()
	binary.Read(r, binary.BigEndian, &es.FlowDataLength)
	binary.Read(r, binary.BigEndian, &es.IncomingVLAN)
	binary.Read(r, binary.BigEndian, &es.IncomingVLANPriority)
	binary.Read(r, binary.BigEndian, &es.OutgoingVLAN)
	binary.Read(r, binary.BigEndian, &es.OutgoingVLANPriority)

	return es, nil
}

// ExtendedRouterFlowRecord gives additional information
// about the layer 3 routing information used to forward
// the packet
type ExtendedRouterFlowRecord struct {
	BaseFlowRecord
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

func (er ExtendedRouterFlowRecord) String() string {
	var out string
	out = fmt.Sprintf("%32s\n\n", er.GetType())
	out += fmt.Sprintf("%32s: %s\n", "Enterprise ID", er.EnterpriseID)
	out += fmt.Sprintf("%32s: %s\n", "Format", er.Format)
	out += fmt.Sprintf("%32s: %d\n", "Flow Data Length", er.FlowDataLength)
	out += fmt.Sprintf("%32s: %s\n", "Next Hop", er.NextHop)
	out += fmt.Sprintf("%32s: %d\n", "Next Hop Source Mask", er.NextHopSourceMask)
	out += fmt.Sprintf("%32s: %d\n", "Next Hop Destination Mask", er.NextHopDestinationMask)
	out += fmt.Sprint("\n")

	return out
}

func decodeExtendedRouterFlowRecord(r *bytes.Reader) (ExtendedRouterFlowRecord, error) {
	er := ExtendedRouterFlowRecord{}
	var extendedRouterAddressType SFlowIPType
	var fdf FlowDataFormat

	binary.Read(r, binary.BigEndian, &fdf)
	er.EnterpriseID, er.Format = fdf.decode()
	binary.Read(r, binary.BigEndian, &er.FlowDataLength)
	binary.Read(r, binary.BigEndian, &extendedRouterAddressType)
	er.NextHop = extendedRouterAddressType.decodeIP(r)
	binary.Read(r, binary.BigEndian, &er.NextHopSourceMask)
	binary.Read(r, binary.BigEndian, &er.NextHopDestinationMask)

	return er, nil

}

// ExtendedGatewayFlowRecord describes information treasured by
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

type ExtendedGatewayFlowRecord struct {
	BaseFlowRecord
	NextHop     net.IP
	AS          uint32
	SourceAS    uint32
	PeerAS      uint32
	ASPathCount uint32
	ASPath      []ASDestination
	Communities []uint32
	LocalPref   uint32
}

type ASPathType uint32

const (
	ASSet      ASPathType = 1
	ASSequence ASPathType = 2
)

func (apt ASPathType) String() string {
	switch apt {
	case ASSet:
		return "AS Set"
	case ASSequence:
		return "AS Sequence"
	}

	return ""
}

type ASDestination struct {
	Type    ASPathType
	Count   uint32
	Members []uint32
}

func (asd ASDestination) String() string {
	switch asd.Type {
	case ASSet:
		return fmt.Sprint("AS Set:", asd.Members)
	case ASSequence:
		return fmt.Sprint("AS Sequence:", asd.Members)
	}
	return ""
}

func (ad *ASDestination) decodePath(r *bytes.Reader) {

	binary.Read(r, binary.BigEndian, &ad.Type)
	binary.Read(r, binary.BigEndian, &ad.Count)
	ad.Members = make([]uint32, ad.Count)
	binary.Read(r, binary.BigEndian, &ad.Members)

}

func decodeExtendedGatewayFlowRecord(r *bytes.Reader) (ExtendedGatewayFlowRecord, error) {
	eg := ExtendedGatewayFlowRecord{}
	var extendedGatewayAddressType SFlowIPType
	var fdf FlowDataFormat
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
		asPath := ASDestination{}
		asPath.decodePath(r)
		eg.ASPath = append(eg.ASPath, asPath)
	}

	binary.Read(r, binary.BigEndian, &communitiesLength)
	eg.Communities = make([]uint32, communitiesLength)

	binary.Read(r, binary.BigEndian, &eg.Communities)
	binary.Read(r, binary.BigEndian, &eg.LocalPref)

	return eg, nil
}

func (eg ExtendedGatewayFlowRecord) String() string {
	var out string
	out = fmt.Sprintf("%32s\n\n", eg.GetType())
	out += fmt.Sprintf("%32s: %s\n", "Enterprise ID", eg.EnterpriseID)
	out += fmt.Sprintf("%32s: %s\n", "Format", eg.Format)
	out += fmt.Sprintf("%32s: %d\n", "Flow Data Length", eg.FlowDataLength)
	out += fmt.Sprintf("%32s: %s\n", "Next Hop", eg.NextHop)
	out += fmt.Sprintf("%32s: %d\n", "AS", eg.AS)
	out += fmt.Sprintf("%32s: %d\n", "Source AS", eg.SourceAS)
	out += fmt.Sprintf("%32s: %d\n", "Peer AS", eg.PeerAS)
	for _, path := range eg.ASPath {
		switch path.Type {
		case ASSet:
			out += fmt.Sprintf("%32s: %d\n", "AS Set", path.Members)
		case ASSequence:
			out += fmt.Sprintf("%32s: %d\n", "AS Sequence", path.Members)
		}
	}

	out += fmt.Sprintf("%32s: %d\n", "Communities", eg.Communities)

	out += fmt.Sprintf("%32s: %d\n", "LocalPref", eg.LocalPref)
	out += fmt.Sprint("\n")

	return out
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

type URLDirection uint32

const (
	URLsrc URLDirection = 1
	URLdst URLDirection = 2
)

func (urld URLDirection) String() string {
	switch urld {
	case URLsrc:
		return "Source address is the server"
	case URLdst:
		return "Destination address is the server"
	}
	return ""
}

type ExtendedURLRecord struct {
	BaseFlowRecord
	Direction URLDirection
	URL       string
	Host      string
}

func decodeExtendedURLRecord(r *bytes.Reader) (ExtendedURLRecord, error) {
	eur := ExtendedURLRecord{}
	var fdf FlowDataFormat
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

func (eur ExtendedURLRecord) String() string {
	var out string
	out = fmt.Sprintf("%32s\n\n", eur.GetType())
	out += fmt.Sprintf("%32s: %s\n", "Enterprise ID", eur.EnterpriseID)
	out += fmt.Sprintf("%32s: %s\n", "Format", eur.Format)
	out += fmt.Sprintf("%32s: %d\n", "Flow Data Length", eur.FlowDataLength)
	out += fmt.Sprintf("%32s: %s\n", "Direction", eur.Direction)
	out += fmt.Sprintf("%32s: %s\n", "URL", eur.URL)
	out += fmt.Sprintf("%32s: %s\n", "Host", eur.Host)

	return out
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

type ExtendedUserFlow struct {
	BaseFlowRecord
	SourceCharSet      CharSet
	SourceUserID       string
	DestinationCharSet CharSet
	DestinationUserID  string
}

type CharSet uint32

const (
	unknown                   CharSet = 2
	csASCII                   CharSet = 3
	csISOLatin1               CharSet = 4
	csISOLatin2               CharSet = 5
	csISOLatin3               CharSet = 6
	csISOLatin4               CharSet = 7
	csISOLatinCyrillic        CharSet = 8
	csISOLatinArabic          CharSet = 9
	csISOLatinGreek           CharSet = 10
	csISOLatinHebrew          CharSet = 11
	csISOLatin5               CharSet = 12
	csISOLatin6               CharSet = 13
	csISOTextComm             CharSet = 14
	csHalfWidthKatakana       CharSet = 15
	csJISEncoding             CharSet = 16
	csShiftJIS                CharSet = 17
	csEUCPkdFmtJapanese       CharSet = 18
	csEUCFixWidJapanese       CharSet = 19
	csISO4UnitedKingdom       CharSet = 20
	csISO11SwedishForNames    CharSet = 21
	csISO15Italian            CharSet = 22
	csISO17Spanish            CharSet = 23
	csISO21German             CharSet = 24
	csISO60DanishNorwegian    CharSet = 25
	csISO69French             CharSet = 26
	csISO10646UTF1            CharSet = 27
	csISO646basic1983         CharSet = 28
	csINVARIANT               CharSet = 29
	csISO2IntlRefVersion      CharSet = 30
	csNATSSEFI                CharSet = 31
	csNATSSEFIADD             CharSet = 32
	csNATSDANO                CharSet = 33
	csNATSDANOADD             CharSet = 34
	csISO10Swedish            CharSet = 35
	csKSC56011987             CharSet = 36
	csISO2022KR               CharSet = 37
	csEUCKR                   CharSet = 38
	csISO2022JP               CharSet = 39
	csISO2022JP2              CharSet = 40
	csISO13JISC6220jp         CharSet = 41
	csISO14JISC6220ro         CharSet = 42
	csISO16Portuguese         CharSet = 43
	csISO18Greek7Old          CharSet = 44
	csISO19LatinGreek         CharSet = 45
	csISO25French             CharSet = 46
	csISO27LatinGreek1        CharSet = 47
	csISO5427Cyrillic         CharSet = 48
	csISO42JISC62261978       CharSet = 49
	csISO47BSViewdata         CharSet = 50
	csISO49INIS               CharSet = 51
	csISO50INIS8              CharSet = 52
	csISO51INISCyrillic       CharSet = 53
	csISO54271981             CharSet = 54
	csISO5428Greek            CharSet = 55
	csISO57GB1988             CharSet = 56
	csISO58GB231280           CharSet = 57
	csISO61Norwegian2         CharSet = 58
	csISO70VideotexSupp1      CharSet = 59
	csISO84Portuguese2        CharSet = 60
	csISO85Spanish2           CharSet = 61
	csISO86Hungarian          CharSet = 62
	csISO87JISX0208           CharSet = 63
	csISO88Greek7             CharSet = 64
	csISO89ASMO449            CharSet = 65
	csISO90                   CharSet = 66
	csISO91JISC62291984a      CharSet = 67
	csISO92JISC62991984b      CharSet = 68
	csISO93JIS62291984badd    CharSet = 69
	csISO94JIS62291984hand    CharSet = 70
	csISO95JIS62291984handadd CharSet = 71
	csISO96JISC62291984kana   CharSet = 72
	csISO2033                 CharSet = 73
	csISO99NAPLPS             CharSet = 74
	csISO102T617bit           CharSet = 75
	csISO103T618bit           CharSet = 76
	csISO111ECMACyrillic      CharSet = 77
	csa71                     CharSet = 78
	csa72                     CharSet = 79
	csISO123CSAZ24341985gr    CharSet = 80
	csISO88596E               CharSet = 81
	csISO88596I               CharSet = 82
	csISO128T101G2            CharSet = 83
	csISO88598E               CharSet = 84
	csISO88598I               CharSet = 85
	csISO139CSN369103         CharSet = 86
	csISO141JUSIB1002         CharSet = 87
	csISO143IECP271           CharSet = 88
	csISO146Serbian           CharSet = 89
	csISO147Macedonian        CharSet = 90
	csISO150                  CharSet = 91
	csISO151Cuba              CharSet = 92
	csISO6937Add              CharSet = 93
	csISO153GOST1976874       CharSet = 94
	csISO8859Supp             CharSet = 95
	csISO10367Box             CharSet = 96
	csISO158Lap               CharSet = 97
	csISO159JISX02121990      CharSet = 98
	csISO646Danish            CharSet = 99
	csUSDK                    CharSet = 100
	csDKUS                    CharSet = 101
	csKSC5636                 CharSet = 102
	csUnicode11UTF7           CharSet = 103
	csISO2022CN               CharSet = 104
	csISO2022CNEXT            CharSet = 105
	csUTF8                    CharSet = 106
	csISO885913               CharSet = 109
	csISO885914               CharSet = 110
	csISO885915               CharSet = 111
	csISO885916               CharSet = 112
	csGBK                     CharSet = 113
	csGB18030                 CharSet = 114
	csOSDEBCDICDF0415         CharSet = 115
	csOSDEBCDICDF03IRV        CharSet = 116
	csOSDEBCDICDF041          CharSet = 117
	csISO115481               CharSet = 118
	csKZ1048                  CharSet = 119
	csUnicode                 CharSet = 1000
	csUCS4                    CharSet = 1001
	csUnicodeASCII            CharSet = 1002
	csUnicodeLatin1           CharSet = 1003
	csUnicodeJapanese         CharSet = 1004
	csUnicodeIBM1261          CharSet = 1005
	csUnicodeIBM1268          CharSet = 1006
	csUnicodeIBM1276          CharSet = 1007
	csUnicodeIBM1264          CharSet = 1008
	csUnicodeIBM1265          CharSet = 1009
	csUnicode11               CharSet = 1010
	csSCSU                    CharSet = 1011
	csUTF7                    CharSet = 1012
	csUTF16BE                 CharSet = 1013
	csUTF16LE                 CharSet = 1014
	csUTF16                   CharSet = 1015
	csCESU8                   CharSet = 1016
	csUTF32                   CharSet = 1017
	csUTF32BE                 CharSet = 1018
	csUTF32LE                 CharSet = 1019
	csBOCU1                   CharSet = 1020
	csWindows30Latin1         CharSet = 2000
	csWindows31Latin1         CharSet = 2001
	csWindows31Latin2         CharSet = 2002
	csWindows31Latin5         CharSet = 2003
	csHPRoman8                CharSet = 2004
	csAdobeStandardEncoding   CharSet = 2005
	csVenturaUS               CharSet = 2006
	csVenturaInternational    CharSet = 2007
	csDECMCS                  CharSet = 2008
	csPC850Multilingual       CharSet = 2009
	csPCp852                  CharSet = 2010
	csPC8CodePage437          CharSet = 2011
	csPC8DanishNorwegian      CharSet = 2012
	csPC862LatinHebrew        CharSet = 2013
	csPC8Turkish              CharSet = 2014
	csIBMSymbols              CharSet = 2015
	csIBMThai                 CharSet = 2016
	csHPLegal                 CharSet = 2017
	csHPPiFont                CharSet = 2018
	csHPMath8                 CharSet = 2019
	csHPPSMath                CharSet = 2020
	csHPDesktop               CharSet = 2021
	csVenturaMath             CharSet = 2022
	csMicrosoftPublishing     CharSet = 2023
	csWindows31J              CharSet = 2024
	csGB2312                  CharSet = 2025
	csBig5                    CharSet = 2026
	csMacintosh               CharSet = 2027
	csIBM037                  CharSet = 2028
	csIBM038                  CharSet = 2029
	csIBM273                  CharSet = 2030
	csIBM274                  CharSet = 2031
	csIBM275                  CharSet = 2032
	csIBM277                  CharSet = 2033
	csIBM278                  CharSet = 2034
	csIBM280                  CharSet = 2035
	csIBM281                  CharSet = 2036
	csIBM284                  CharSet = 2037
	csIBM285                  CharSet = 2038
	csIBM290                  CharSet = 2039
	csIBM297                  CharSet = 2040
	csIBM420                  CharSet = 2041
	csIBM423                  CharSet = 2042
	csIBM424                  CharSet = 2043
	csIBM500                  CharSet = 2044
	csIBM851                  CharSet = 2045
	csIBM855                  CharSet = 2046
	csIBM857                  CharSet = 2047
	csIBM860                  CharSet = 2048
	csIBM861                  CharSet = 2049
	csIBM863                  CharSet = 2050
	csIBM864                  CharSet = 2051
	csIBM865                  CharSet = 2052
	csIBM868                  CharSet = 2053
	csIBM869                  CharSet = 2054
	csIBM870                  CharSet = 2055
	csIBM871                  CharSet = 2056
	csIBM880                  CharSet = 2057
	csIBM891                  CharSet = 2058
	csIBM903                  CharSet = 2059
	csIBBM904                 CharSet = 2060
	csIBM905                  CharSet = 2061
	csIBM918                  CharSet = 2062
	csIBM1026                 CharSet = 2063
	csIBMEBCDICATDE           CharSet = 2064
	csEBCDICATDEA             CharSet = 2065
	csEBCDICCAFR              CharSet = 2066
	csEBCDICDKNO              CharSet = 2067
	csEBCDICDKNOA             CharSet = 2068
	csEBCDICFISE              CharSet = 2069
	csEBCDICFISEA             CharSet = 2070
	csEBCDICFR                CharSet = 2071
	csEBCDICIT                CharSet = 2072
	csEBCDICPT                CharSet = 2073
	csEBCDICES                CharSet = 2074
	csEBCDICESA               CharSet = 2075
	csEBCDICESS               CharSet = 2076
	csEBCDICUK                CharSet = 2077
	csEBCDICUS                CharSet = 2078
	csUnknown8BiT             CharSet = 2079
	csMnemonic                CharSet = 2080
	csMnem                    CharSet = 2081
	csVISCII                  CharSet = 2082
	csVIQR                    CharSet = 2083
	csKOI8R                   CharSet = 2084
	csHZGB2312                CharSet = 2085
	csIBM866                  CharSet = 2086
	csPC775Baltic             CharSet = 2087
	csKOI8U                   CharSet = 2088
	csIBM00858                CharSet = 2089
	csIBM00924                CharSet = 2090
	csIBM01140                CharSet = 2091
	csIBM01141                CharSet = 2092
	csIBM01142                CharSet = 2093
	csIBM01143                CharSet = 2094
	csIBM01144                CharSet = 2095
	csIBM01145                CharSet = 2096
	csIBM01146                CharSet = 2097
	csIBM01147                CharSet = 2098
	csIBM01148                CharSet = 2099
	csIBM01149                CharSet = 2100
	csBig5HKSCS               CharSet = 2101
	csIBM1047                 CharSet = 2102
	csPTCP154                 CharSet = 2103
	csAmiga1251               CharSet = 2104
	csKOI7switched            CharSet = 2105
	csBRF                     CharSet = 2106
	csTSCII                   CharSet = 2107
	csCP51932                 CharSet = 2108
	cswindows874              CharSet = 2109
	cswindows1250             CharSet = 2250
	cswindows1251             CharSet = 2251
	cswindows1252             CharSet = 2252
	cswindows1253             CharSet = 2253
	cswindows1254             CharSet = 2254
	cswindows1255             CharSet = 2255
	cswindows1256             CharSet = 2256
	cswindows1257             CharSet = 2257
	cswindows1258             CharSet = 2258
	csTIS620                  CharSet = 2259
	cs50220                   CharSet = 2260
	reserved                  CharSet = 3000
)

func decodeExtendedUserFlow(r *bytes.Reader) (ExtendedUserFlow, error) {
	eu := ExtendedUserFlow{}
	var fdf FlowDataFormat
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

func (eu ExtendedUserFlow) String() string {
	var out string
	out = fmt.Sprintf("%32s\n\n", eu.GetType())
	out += fmt.Sprintf("%32s: %s\n", "Enterprise ID", eu.EnterpriseID)
	out += fmt.Sprintf("%32s: %s\n", "Format", eu.Format)
	out += fmt.Sprintf("%32s: %d\n", "Flow Data Length", eu.FlowDataLength)
	out += fmt.Sprintf("%32s: %d\n", "Source Character Set", eu.SourceCharSet)
	out += fmt.Sprintf("%32s: %s\n", "Source User ID", eu.SourceUserID)
	out += fmt.Sprintf("%32s: %d\n", "Destination Character Set", eu.DestinationCharSet)
	out += fmt.Sprintf("%32s: %s\n", "Destination User ID", eu.DestinationUserID)

	return out
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

type BaseCounterRecord struct {
	EnterpriseID   EnterpriseID
	Format         CounterRecordType
	FlowDataLength uint32
}

func (bcr BaseCounterRecord) GetType() CounterRecordType {
	switch bcr.Format {
	case TypeGenericInterfaceCounters:
		return TypeGenericInterfaceCounters
	case TypeEthernetInterfaceCounters:
		return TypeEthernetInterfaceCounters
	case TypeTokenRingInterfaceCounters:
		return TypeTokenRingInterfaceCounters
	case Type100BaseVGInterfaceCounters:
		return Type100BaseVGInterfaceCounters
	case TypeVLANCounters:
		return TypeVLANCounters
	case TypeProcessorCounters:
		return TypeProcessorCounters

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

type GenericInterfaceCounters struct {
	BaseCounterRecord
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

func (gic GenericInterfaceCounters) String() string {
	var out string
	//out = fmt.Sprintf("%32s\n\n", gic.GetType())
	out += fmt.Sprintf("%32s: %s\n", "Enterprise ID", gic.EnterpriseID)
	out += fmt.Sprintf("%32s: %s\n", "Record Type", gic.Format)
	out += fmt.Sprintf("%32s: %d\n", "Flow Data Length", gic.FlowDataLength)

	out += fmt.Sprintf("%32s: %d\n", "ifIndex", gic.IfIndex)
	out += fmt.Sprintf("%32s: %d\n", "ifType", gic.IfType)
	out += fmt.Sprintf("%32s: %d\n", "ifSpeed", gic.IfSpeed)
	out += fmt.Sprintf("%32s: %d\n", "ifDirection", gic.IfDirection)
	out += fmt.Sprintf("%32s: %d\n", "ifStatus", gic.IfStatus)
	out += fmt.Sprintf("%32s: %d\n", "ifInOctets", gic.IfInOctets)
	out += fmt.Sprintf("%32s: %d\n", "ifInUcastPkts", gic.IfInUcastPkts)
	out += fmt.Sprintf("%32s: %d\n", "ifInMulticastPkts", gic.IfInMulticastPkts)
	out += fmt.Sprintf("%32s: %d\n", "ifInBroadcastPkts", gic.IfInBroadcastPkts)
	out += fmt.Sprintf("%32s: %d\n", "ifInDiscards", gic.IfInDiscards)
	out += fmt.Sprintf("%32s: %d\n", "ifInErrors", gic.IfInErrors)
	out += fmt.Sprintf("%32s: %d\n", "ifInUnknownProtos", gic.IfInUnknownProtos)
	out += fmt.Sprintf("%32s: %d\n", "ifOutOctets", gic.IfOutOctets)
	out += fmt.Sprintf("%32s: %d\n", "ifOutUcastPkts", gic.IfOutUcastPkts)
	out += fmt.Sprintf("%32s: %d\n", "ifOutMulticastPkts", gic.IfOutMulticastPkts)
	out += fmt.Sprintf("%32s: %d\n", "ifOUtBroadcastPkts", gic.IfOutBroadcastPkts)
	out += fmt.Sprintf("%32s: %d\n", "ifOUtDiscards", gic.IfOutDiscards)
	out += fmt.Sprintf("%32s: %d\n", "ifOutErrors", gic.IfOutErrors)
	out += fmt.Sprintf("%32s: %d\n", "ifPromiscuousMode", gic.IfPromiscuousMode)
	return out
}

func decodeGenericInterfaceCounters(r *bytes.Reader) (GenericInterfaceCounters, error) {
	gic := GenericInterfaceCounters{}
	var cdf CounterDataFormat

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

type EthernetCounters struct {
	BaseCounterRecord

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

func (ec EthernetCounters) String() string {
	var out string
	out += fmt.Sprintf("%32s: %s\n", "Enterprise ID", ec.EnterpriseID)
	out += fmt.Sprintf("%32s: %s\n", "Record Type", ec.Format)
	out += fmt.Sprintf("%32s: %d\n", "Flow Data Length", ec.FlowDataLength)

	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsAlignmentErrors", ec.Dot3StatsAlignmentErrors)
	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsFCSErrors", ec.Dot3StatsFCSErrors)
	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsSingleCollisionFrames", ec.Dot3StatsSingleCollisionFrames)
	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsMultipleCollisionFrames", ec.Dot3StatsMultipleCollisionFrames)
	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsSQETestErrors", ec.Dot3StatsSQETestErrors)
	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsDeferredTransmissions", ec.Dot3StatsDeferredTransmissions)
	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsLateCollisions", ec.Dot3StatsLateCollisions)
	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsExcessiveCollisions", ec.Dot3StatsExcessiveCollisions)
	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsInternalMacTransmitErrors", ec.Dot3StatsInternalMacTransmitErrors)
	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsCarrierSenseErrors", ec.Dot3StatsCarrierSenseErrors)
	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsFrameTooLongs", ec.Dot3StatsFrameTooLongs)
	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsInternalMacReceiveErrors", ec.Dot3StatsInternalMacReceiveErrors)
	out += fmt.Sprintf("%32s: %d\n", "Dot3StatsSymbolErrors", ec.Dot3StatsSymbolErrors)
	return out
}

func decodeEthernetCounters(r *bytes.Reader) (EthernetCounters, error) {
	ec := EthernetCounters{}
	var cdf CounterDataFormat

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
