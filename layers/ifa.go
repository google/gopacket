package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

const (
	// IFA version
	IFAVersion uint8 = 0x02
	// GNS disabled, metadata in an IFA zone is defined by
	// the LNS of each hop
	NoGlobalNameSpace = 0x0f
)

// IFAPortSpeed interface speed used to specified the egress
// interface port speed in IFA.
// Encodings are 0–10Gbps, 1–25Gbps, 2–40Gbps, 3–50Gbps,
// 4–100Gbps, 5–200Gbps, 6–400Gbps.
type IFAPortSpeed uint8

const (
	IFAPortSpeed10G IFAPortSpeed = iota
	IFAPortSpeed25G
	IFAPortSpeed40G
	IFAPortSpeed100G
	IFAPortSpeed200G
)

// Register IFA layer
func decodeIFA(data []byte, p gopacket.PacketBuilder) error {
	ifa := &IFA{}

	err := ifa.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(ifa)
	// TODO: should we use the application layer
	//       and create two layer type,
	//       one for header and one for metadata
	p.SetApplicationLayer(ifa)

	return nil
}

/*
IFA header is inserted between layer 3 and 4 by the initiator node. Then
Metadata header, fragment, checksum and data are inserted between layer
4 and payload or at the end of the packet just before the FCS.
Each node append metadata to the stack and terminating node remove all
IFA headers/data from the packet, forward it and generates and sends a
report to am IPFIX collector.

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	~                                                               ~
	|                        IP Header                              |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	~                                                               ~
	|                       IFA Header                              |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	~                                                               ~
	|                     Layer 4 Header                            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	~                                                               ~
	|                   IFA Metadata Header                         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	~                                                               ~
	|                    IFA Metadata Stack                         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	~                                                               ~
	|                          Payload                              |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	~                                                               ~
	|                   IFA Metadata Stack                          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	~                                                               ~
	|                   IFA Metadata Header                         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                            FCS                                |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type IFA struct {
	BaseLayer
	Header         IFAHeader
	MetadataHeader IFAMetadataHeader
	Metadatas      []IFAMetadata
}

// LayerType returns LayerTypeIFA
func (i *IFA) LayerType() gopacket.LayerType {
	return LayerTypeIFA
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (i *IFA) NextLayerType() gopacket.LayerType {
	return i.Header.NextHeader.LayerType()
}

func (i *IFA) Payload() []byte {
	return i.BaseLayer.Payload
}

func (d *IFA) CanDecode() gopacket.LayerClass {
	return LayerTypeIFA
}

// DecodeFromBytes decodes the given bytes into this layer
func (i *IFA) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// decode header
	if err := i.Header.decodeFromBytes(&data); err != nil {
		return err
	}
	if i.Header.GlobalNameSpace != NoGlobalNameSpace {
		return fmt.Errorf("global name space identifier not supported")
	}
	if i.Header.Checksum {
		return fmt.Errorf("checksum header not supported")
	}
	if i.Header.MetadataFragment {
		return fmt.Errorf("metadata fragment header not supported")
	}
	if i.Header.TailStamp {
		return fmt.Errorf("tail stamp metadata not supported")
	}
	if len(data) == 0 {
		return nil
	}

	// decode metadata header
	if err := i.MetadataHeader.decodeFromBytes(&data); err != nil {
		return err
	} else if len(data) == 0 {
		return nil
	}

	// validate metadata stack length
	if len(data)%4 != 0 {
		return fmt.Errorf(
			"invalid metadata stack length, %d is not a multiple of 4 octets",
			len(data))
	}
	if int(i.MetadataHeader.CurrentLength)*4 < len(data) {
		return fmt.Errorf(
			"invalid metadata stack length, expect %d got %d",
			i.MetadataHeader.CurrentLength*4, len(data))
	}
	remainingBytes := int(i.MetadataHeader.CurrentLength) * 4

	// TODO: parse optional checksum header

	// TODO: parse optional metadata fragmentation header

	// TODO: skip layer 4 herader

	// decode metadata
	if !i.Header.TailStamp {
		for remainingBytes > 0 {
			m := IFAMetadata{}
			if err := m.decodeFromBytes(&data); err != nil {
				return err
			}
			remainingBytes -= m.Len()
			i.Metadatas = append(i.Metadatas, m)
		}

	}

	if len(data) > 0 {
		i.BaseLayer.Payload = data
	}

	return nil
}

/*
IFA Header:

	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| Ver=2 |  GNS  |NextHdr = IP_xx|R|R|R|M|T|I|T|C|   Max Length  |
	|       |       |               | | | |F|S| |A| |               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type IFAHeader struct {
	Version          uint8
	GlobalNameSpace  uint8
	NextHeader       IPProtocol
	MetadataFragment bool
	TailStamp        bool
	Inband           bool
	TurnAround       bool
	Checksum         bool
	MaxLength        uint8
}

// Len returns the data length in octet required by IFA header
func (mh IFAHeader) Len() int {
	return 0.5 /* version */ +
		0.5 /* GNS */ +
		1 /* next header */ +
		1 /* flags */ +
		1 /* max length */
}

func (h *IFAHeader) decodeFromBytes(data *[]byte) error {
	if len(*data) < h.Len() {
		return fmt.Errorf("invalid header length")
	}

	h.Version = (*data)[0] >> 4
	if h.Version != IFAVersion {
		return fmt.Errorf("IFA version %d not supported", h.Version)
	}
	h.GlobalNameSpace = (*data)[0] & 0x0f
	h.NextHeader = IPProtocol((*data)[1])
	h.MetadataFragment = (*data)[2]&0x10 != 0
	h.TailStamp = (*data)[2]&0x08 != 0
	h.Inband = (*data)[2]&0x04 != 0
	h.TurnAround = (*data)[2]&0x02 != 0
	h.Checksum = (*data)[2]&0x01 != 0
	h.MaxLength = (*data)[3]

	// remove what was read from buffer
	*data = (*data)[h.Len():]

	return nil
}

/*
The IFA metadata header:

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| Request Vector| Action Vector |   Hop Limit   | Current Length|
	|               |L|C|R|R|R|R|R|R|               |               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type IFAMetadataHeader struct {
	RequestVector uint8
	Loss          bool
	Color         bool
	HopLimit      uint8
	CurrentLength uint8
}

// Len returns the data length in octet required by IFA metadata header
func (mh IFAMetadataHeader) Len() int {
	return 1 /* request vector */ +
		1 /* action vector */ +
		1 /* hop limit */ +
		1 /* current length */
}

func (mh *IFAMetadataHeader) decodeFromBytes(data *[]byte) error {
	if len(*data) < mh.Len() {
		return fmt.Errorf("invalid metadata header length")
	}

	mh.RequestVector = (*data)[0]
	mh.Loss = (*data)[1]&0x80 != 0
	mh.Color = (*data)[1]&0x40 != 0
	mh.HopLimit = (*data)[2]
	mh.CurrentLength = (*data)[3]

	// remove what was read from buffer
	*data = (*data)[mh.Len():]

	return nil
}

/*
IFA Metadata:

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  LNS  |                     Device ID                         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                                                               |
	|                                                               |
	~                LNS/GNS defined metadata (contd)               ~
	.                                                               .
	.                                                               .
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type IFAMetadata struct {
	LocalNameSpace         uint8
	DeviceID               uint32
	IPTTL                  uint8
	EgressPortSpeed        IFAPortSpeed
	Congestion             uint8
	QueueID                uint8
	RXTimestampSeconds     uint32
	EgressSystemPort       uint16
	IngressSystemPort      uint16
	RXTimestampNanoSeconds uint32
	ResidenceTime          uint32
	Reserved               [12]byte
}

// Len returns the data length in octet required by IFA metadata
func (mh IFAMetadata) Len() int {
	return 0.5 + 2.5 + 1 /* LNS, device, ttl */ +
		0.5 + 0.25 + 0.75 + 2.5 /* speed, congestion, queue, ts sec */ +
		2 + 2 /* if index in and out */ +
		4 /* ts nano */ +
		4 /* residence nano */ +
		12 /* reserved */
}

func (m *IFAMetadata) decodeFromBytes(data *[]byte) error {
	if len(*data) < m.Len() {
		return fmt.Errorf("invalid metadata header length")
	}

	// remove what was read from buffer
	m.LocalNameSpace = (*data)[0] >> 4
	m.DeviceID = binary.BigEndian.Uint32(
		[]byte{
			0x00,
			(*data)[0] & 0x0f,
			(*data)[1],
			(*data)[2],
		},
	)
	m.IPTTL = (*data)[3]
	m.EgressPortSpeed = IFAPortSpeed((*data)[4] >> 4)
	m.Congestion = (*data)[4] & 0x0c
	m.QueueID = (((*data)[4] & 0x03) << 4) | ((*data)[5] >> 4)
	m.RXTimestampSeconds = binary.BigEndian.Uint32(
		[]byte{
			0x00,
			(*data)[5] & 0x0f,
			(*data)[6],
			(*data)[7],
		},
	)
	m.EgressSystemPort = binary.BigEndian.Uint16((*data)[8:10])
	m.IngressSystemPort = binary.BigEndian.Uint16((*data)[10:12])
	m.RXTimestampNanoSeconds = binary.BigEndian.Uint32((*data)[12:16])
	m.ResidenceTime = binary.BigEndian.Uint32((*data)[16:20])
	copy(m.Reserved[:], (*data)[20:])

	// remove what was read from buffer
	*data = (*data)[m.Len():]

	return nil
}
