/* LICENSE */
/*
This layer decodes IPFIX version 10 datagrams.

The specification can be found here: https://datatracker.ietf.org/doc/html/rfc7011

This decoder only decode Data Records if the datagram also contains Template or
Option Template associated to it. Otherwise, Data Records will only contains
bytes. It provides a method to decode raw bytes with a given template.
This decoder does no parse well known Data fields defined in IANA-IPFIX
https://www.iana.org/assignments/ipfix/ipfix.xhtml

TODO:
- support encoding method `SerializeTo`
- use gopacket DecodeFeedback
- benchmark a more consequent pcap file
- optimize data record to no store raw bytes if it was properly decoded with a
  template
*/

package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

const (
	// Version word in the Message Header
	Version uint16 = 0x000a
	// EnterpriseBit used in the Field Specifier
	EnterpriseBit uint16 = 0x8000
	// VariableLength used in the Field Specifier
	VariableLength uint16 = 0xffff
)

// Register IPFIX layer

func decodeIPFIX(data []byte, p gopacket.PacketBuilder) error {
	ipfix := &IPFIX{
		Templates: make(map[IPFIXSetIDType]IPFIXTemplateAccessor),
	}

	err := ipfix.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(ipfix)
	p.SetApplicationLayer(ipfix)

	return nil
}

// IPFIXFieldFunc function call to iter Template/OptionTemplate Field Specifiers
type IPFIXFieldFunc func(fs *IPFIXFieldSpecifier) error

// IPFIXTemplateAccessor interface to access Template and OptionTemplate
type IPFIXTemplateAccessor interface {
	GetID() IPFIXSetIDType
	GetMinDataRecordLength() uint16
	IterFieldSpecifier(fn IPFIXFieldFunc) error
}

// IPFIX is the outermost container which holds packet header and holds
// at least one template or one data set
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                            Header                             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  ---
//   |                       Template Set #1                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   T
//   |                   Option Template Set #2                      |   M
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   P
//   ...                                                                 L
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Template Set #n                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  ---
//   |                  Data Sets of Template #1                     |
//   |                       Data Record #1                          |
//   ...
//   |                       Data Record #n                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |               Data Sets of Option Template #2                 |   D
//   |                       Data Record #1                          |   A
//   ...                                                                 T
//   |                       Data Record #n                          |   A
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   ...
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                  Data Sets of Template #n                     |
//   |                       Data Record #1                          |
//   ...
//   |                       Data Record #n                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  ---
//
type IPFIX struct {
	BaseLayer

	// Header message
	Header IPFIXMessageHeader
	// Template and Option Template sets map referenced by their ID
	Templates map[IPFIXSetIDType]IPFIXTemplateAccessor
	// Templates map[IPFIXSetIDType]*IPFIXTemplateRecord
	// Data sets contains in the message
	// Only decoded if the message contains the corresponding template.
	Data []IPFIXDataSet
}

// LayerType returns LayerTypeIPFIX
func (i *IPFIX) LayerType() gopacket.LayerType { return LayerTypeIPFIX }

// NextLayerType returns the layer type contained by this DecodingLayer.
func (i *IPFIX) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Payload returns an empty byte slice are IPFIX message does not contains payload
func (i *IPFIX) Payload() []byte { return nil }

// DecodeFromBytes decodes the given bytes into this layer.
func (i *IPFIX) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// decode message header
	if err := i.Header.decodeFromBytes(&data); err != nil {
		return err
	}

	for len(data) > 0 {
		h := &IPFIXSetHeader{}
		if err := h.decodeFromBytes(&data); err != nil {
			return err
		}
		switch h.ID {
		case IPFIXSetIDTypeTemplate:
			t := &IPFIXTemplateRecord{Header: *h}
			if err := t.decodeFromBytes(&data); err == nil {
				i.Templates[t.ID] = t
			} else {
				return err
			}
		case IPFIXSetIDTypeOptionTemplate:
			ot := &IPFIXOptionTemplateRecord{Header: *h}
			if err := ot.decodeFromBytes(&data); err == nil {
				i.Templates[ot.ID] = ot
			} else {
				return err
			}
		default:
			d := &IPFIXDataSet{Header: *h}
			t := i.Templates[h.ID]
			if err := d.decodeFromBytes(&data, t); err != nil {
				return err
			}
			i.Data = append(i.Data, *d)
		}
	}
	return nil
}

// IPFIXMessageHeader is a Message Header (RFC 7011 section 3.1)
//
// The format of the Message Header on the wire is:
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       Version Number          |            Length             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                           Export Time                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Sequence Number                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Observation Domain ID                      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IPFIXMessageHeader struct {
	// Version of IPFIX to which this Message conforms.  The value of
	// this field is 0x000a for the current version, incrementing by one
	// the version used in the NetFlow services export version 9
	Version uint16
	// Total length of the IPFIX Message, measured in octets, including
	// Message Header and Set(s).
	Length uint16
	// Time at which the IPFIX Message Header leaves the Exporter,
	// expressed in seconds since the UNIX epoch of 1 January 1970 at
	// 00:00 UTC, encoded as an unsigned 32-bit integer.
	ExportTime uint32
	// Incremental sequence counter modulo 2^32 of all IPFIX Data Records
	// sent in the current stream from the current Observation Domain by
	// the Exporting Process.
	SequenceNumber uint32
	// A 32-bit identifier of the Observation Domain that is locally
	// unique to the Exporting Process.  The Exporting Process uses the
	// Observation Domain ID to uniquely identify to the Collecting
	// Process the Observation Domain that metered the Flows.
	ObservationDomainID uint32
}

// Len returns the data length in octet required by IPFIX header message
func (mh IPFIXMessageHeader) Len() int {
	return 2 /* version */ + 2 /* length */ + 4 /* export time*/ + 4 /* sequence number */ + 4 /* observation domain id */
}

func (mh *IPFIXMessageHeader) decodeFromBytes(data *[]byte) error {
	if len(*data) < mh.Len() {
		return fmt.Errorf("invalid message header length")
	}

	*data, mh.Version = (*data)[2:], binary.BigEndian.Uint16((*data)[:2])
	*data, mh.Length = (*data)[2:], binary.BigEndian.Uint16((*data)[:2])
	*data, mh.ExportTime = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, mh.SequenceNumber = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, mh.ObservationDomainID = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])

	if mh.Version != Version {
		return fmt.Errorf("invalid message header version")
	}

	if len(*data) < int(mh.Length)-mh.Len() {
		return fmt.Errorf("invalid data length")
	}

	return nil
}

// IPFIXSetIDType identifies the Set.
// A value of 2 is reserved for Template Sets.
// A value of 3 is reserved for Options Template Sets. Values from 4
// to 255 are reserved for future use. Values 256 and above are used
// for Data Sets. The Set ID values of 0 and 1 are not used, for
// historical reasons [RFC3954].
type IPFIXSetIDType uint16

const (
	// IPFIXSetIDTypeTemplate tempalte ID
	IPFIXSetIDTypeTemplate IPFIXSetIDType = 2 // Template ID
	// IPFIXSetIDTypeOptionTemplate tempalte ID
	IPFIXSetIDTypeOptionTemplate IPFIXSetIDType = 3
)

// IPFIXSetHeader is a Set Header common to all three Set types (RFC 7011 section 3.3.2)
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |          Set ID               |          Length               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IPFIXSetHeader struct {
	// Identifies the Set. A value of 2 is reserved for Template Sets.
	// A value of 3 is reserved for Options Template Sets. Values from 4
	// to 255 are reserved for future use. Values 256 and above are used
	// for Data Sets. The Set ID values of 0 and 1 are not used, for
	// historical reasons [RFC3954].
	ID IPFIXSetIDType
	// Total length of the Set, in octets, including the Set Header, all
	// records, and the optional padding. Because an individual Set MAY
	// contain multiple records, the Length value MUST be used to
	// determine the position of the next Set.
	Length uint16
}

// Len returns the length in octet requires by Set header
func (sh IPFIXSetHeader) Len() int {
	return 2 /* set id */ + 2 /* length */
}

func (sh *IPFIXSetHeader) decodeFromBytes(data *[]byte) error {
	if len(*data) < sh.Len() {
		*data = []byte{}
		return fmt.Errorf("invalid set header length")
	}

	*data, sh.ID = (*data)[2:], IPFIXSetIDType(binary.BigEndian.Uint16((*data)[:2]))
	*data, sh.Length = (*data)[2:], binary.BigEndian.Uint16((*data)[:2])

	switch {
	case sh.ID <= 1:
		return fmt.Errorf("invalid set header, ID %d reserved for legacy", sh.ID)
	case sh.ID >= 4 && sh.ID <= 255:
		return fmt.Errorf("invalid set header, ID %d reserved for future use", sh.ID)
	}

	if len(*data) < int(sh.Length)-sh.Len() {
		return fmt.Errorf("invalid data length")
	}

	return nil
}

// IPFIXTemplateRecord contains any combination of IANA-assigned and/or
// enterprise-specific Information Element identifiers (RFC 7011 section 3.4.1)
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |      Template ID (> 255)      |         Field Count           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Field Specifiers                                              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   ...
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Field Specifiers                                              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   The struct also contains the set header for convenience.
type IPFIXTemplateRecord struct {
	// Set header
	Header IPFIXSetHeader
	// Each Template Record is given a unique Template ID in the range
	// 256 to 65535.  This uniqueness is local to the Transport Session
	// and Observation Domain that generated the Template ID.
	ID IPFIXSetIDType
	// Number of Field Specifiers in this Template Record.
	FieldCount uint16
	// List of Field Specifiers in that template record.
	// Order matter here, as content will be decoded with that order.
	Fields []IPFIXFieldSpecifier

	// for each template compute the minimum length an associated data record
	// can contains. That helps to iter over multiple data records in the same
	// set.
	minDataRecordLength uint16
}

// Len returns the requires lenght in octet for a Template
// Set Header length is taken into account.
func (tr IPFIXTemplateRecord) Len() int {
	return IPFIXSetHeader{}.Len() + 2 /* template id */ + 2 /* field count */
}

func (tr *IPFIXTemplateRecord) decodeFromBytes(data *[]byte) error {
	if len(*data) < tr.Len()-tr.Header.Len() {
		*data = []byte{}
		return fmt.Errorf("invalid template record length")
	}

	*data, tr.ID = (*data)[2:], IPFIXSetIDType(binary.BigEndian.Uint16((*data)[:2]))
	*data, tr.FieldCount = (*data)[2:], binary.BigEndian.Uint16((*data)[:2])

	tr.Fields = make([]IPFIXFieldSpecifier, tr.FieldCount)
	dataRead := 0
	for i := 0; i < len(tr.Fields); i++ {
		if err := tr.Fields[i].decodeFromBytes(data); err != nil {
			return err
		}
		dataRead += tr.Fields[i].Len()
		tr.minDataRecordLength += tr.Fields[i].FieldLength
	}

	// template set can only contains one template record
	// remaining octet corresponding to padding  see RFC 7011 section 3.1.1
	padding := int(tr.Header.Length) - (dataRead + tr.Len())
	if padding > 0 {
		if padding%4 != 0 {
			return fmt.Errorf("invalid template record padding length")
		}
		for _, b := range (*data)[:padding] {
			if b != 0x00 {
				return fmt.Errorf("invalid template record padding value")
			}
		}
		*data = (*data)[padding:]
	}

	return nil
}

// GetMinDataRecordLength returns the minimum length in octet a record
// corresponding to the Template must have
func (tr *IPFIXTemplateRecord) GetMinDataRecordLength() uint16 {
	return uint16(tr.minDataRecordLength)
}

// GetID returns the Template ID
func (tr *IPFIXTemplateRecord) GetID() IPFIXSetIDType {
	return tr.ID
}

// IterFieldSpecifier iterates all Template field specifier and apply the given
// function to them
func (tr *IPFIXTemplateRecord) IterFieldSpecifier(fn IPFIXFieldFunc) error {
	for _, fs := range tr.Fields {
		if err := fn(&fs); err != nil {
			return err
		}
	}
	return nil
}

// IPFIXOptionTemplateRecord contains any combination of IANA-assigned and/or
// enterprise-specific Information Element identifiers (RFC 7011 section 3.4.2.2)
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |      Template ID (> 255)      |         Field Count           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       Scope Field Count       | Field Specifiers              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Field Specifiers                                              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   ...
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Field Specifiers                                              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   The struct also contains the set header for convenience.
type IPFIXOptionTemplateRecord struct {
	// Set header
	Header IPFIXSetHeader
	// Each Option Template Record is given a unique Template ID in the range
	// 256 to 65535.  This uniqueness is local to the Transport Session
	// and Observation Domain that generated the Template ID.
	ID IPFIXSetIDType
	// Number of Field Specifiers in this Option Template Record.
	FieldCount uint16
	// Number of scope fields in this Options Template Record.  The Scope
	// Fields are normal Fields, except that they are interpreted as
	// scope at the Collector.  A scope field count of N specifies that
	// the first N Field Specifiers in the Template Record are Scope
	// Fields.  The Scope Field Count MUST NOT be zero.
	ScopeFieldCount uint16
	// List of Scope Field Specifiers in that template record.
	// Order matter here, as content will be decoded with that order.
	ScopeFields []IPFIXFieldSpecifier
	// List of Field Specifiers in that template record.
	// Order matter here, as content will be decoded with that order.
	Fields []IPFIXFieldSpecifier

	// for each template compute the minimum length an associated data record
	// can contains. That helps to iter over multiple data records in the same
	// set.
	minDataRecordLength uint16
}

// Len returns the requires lenght in octet for an Option Template
// Set Header length is taken into account.
func (otr IPFIXOptionTemplateRecord) Len() int {
	return IPFIXSetHeader{}.Len() + 2 /* template id */ + 2 /* field count */ + 2 /* scope field count */
}

func (otr *IPFIXOptionTemplateRecord) decodeFromBytes(data *[]byte) error {
	if len(*data) < otr.Len()-otr.Header.Len() {
		*data = []byte{}
		return fmt.Errorf("invalid option template record length")
	}

	*data, otr.ID = (*data)[2:], IPFIXSetIDType(binary.BigEndian.Uint16((*data)[:2]))
	*data, otr.FieldCount = (*data)[2:], binary.BigEndian.Uint16((*data)[:2])
	*data, otr.ScopeFieldCount = (*data)[2:], binary.BigEndian.Uint16((*data)[:2])

	if otr.ScopeFieldCount < 1 {
		return fmt.Errorf("invalid scope field count")
	}

	dataRead := 0

	otr.ScopeFields = make([]IPFIXFieldSpecifier, otr.ScopeFieldCount)
	for i := 0; i < len(otr.ScopeFields); i++ {
		if err := otr.ScopeFields[i].decodeFromBytes(data); err != nil {
			return err
		}
		dataRead += otr.ScopeFields[i].Len()
		otr.minDataRecordLength += otr.ScopeFields[i].FieldLength
	}

	otr.Fields = make([]IPFIXFieldSpecifier, otr.FieldCount-otr.ScopeFieldCount)
	for i := 0; i < len(otr.Fields); i++ {
		if err := otr.Fields[i].decodeFromBytes(data); err != nil {
			return err
		}
		dataRead += otr.Fields[i].Len()
		otr.minDataRecordLength += otr.Fields[i].FieldLength
	}

	// option template set can only contains one option template record
	// remaining octet corresponding to padding see RFC 7011 section 3.1.1
	padding := int(otr.Header.Length) - (dataRead + otr.Len())
	if padding > 0 {
		if padding%4 != 0 {
			return fmt.Errorf("invalid option template set padding length")
		}
		for _, b := range (*data)[:padding] {
			if b != 0x00 {
				return fmt.Errorf("invalid option template set padding value")
			}
		}
		*data = (*data)[padding:]
	}

	return nil
}

// GetMinDataRecordLength returns the minimum length in octet a record
// corresponding to the Option Template must have
func (otr *IPFIXOptionTemplateRecord) GetMinDataRecordLength() uint16 {
	return uint16(otr.minDataRecordLength)
}

// GetID returns the Option Template ID
func (otr *IPFIXOptionTemplateRecord) GetID() IPFIXSetIDType {
	return otr.ID
}

// IterFieldSpecifier iterates all Option Template field specifier and apply the
// given function to them
func (otr *IPFIXOptionTemplateRecord) IterFieldSpecifier(fn IPFIXFieldFunc) error {
	for _, fs := range otr.ScopeFields {
		if err := fn(&fs); err != nil {
			return err
		}
	}

	for _, fs := range otr.Fields {
		if err := fn(&fs); err != nil {
			return err
		}
	}

	return nil
}

// IPFIXFieldSpecifier is a Field Specifier (RFC 7011 section 3.2)
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |E|  Information Element ident. |        Field Length           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                      Enterprise Number                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IPFIXFieldSpecifier struct {
	// Enterprise bit.  This is the first bit of the Field Specifier.  If
	// this bit is zero, the Information Element identifier identifies an
	// Information Element in [IANA-IPFIX], and the four-octet Enterprise
	// Number field MUST NOT be present.  If this bit is one, the
	// Information Element identifier identifies an enterprise-specific
	// Information Element, and the Enterprise Number field MUST be
	// present.
	EnterpriseBit bool
	// The length of the corresponding encoded Information Element, in
	// octets.  Refer to [IANA-IPFIX].  The Field Length may be smaller
	// than that listed in [IANA-IPFIX] if the reduced-size encoding is
	// used.  The value 65535 is reserved for variable-length Information
	// ElementID.
	FieldLength uint16
	// A numeric value that represents the Information Element.  Refer to
	// [IANA-IPFIX].
	InformationElementID uint16
	// IANA enterprise number [IANA-PEN] of the authority defining the
	// Information Element identifier in this Template Record.
	EnterpriseNumber uint32
}

// Len returns the length in octet for Field Specifier
//   * 4 for IANA Information Element
//   * 8 for enterprise-specific Information Element
func (fs IPFIXFieldSpecifier) Len() int {
	if fs.EnterpriseBit {
		return 2 /* field length */ + 2 /* id */ + 4 /* enterprise id */
	}
	return 2 /* field length */ + 2 /* id */
}

func (fs *IPFIXFieldSpecifier) decodeFromBytes(data *[]byte) error {
	if len(*data) < fs.Len() {
		*data = []byte{}
		return fmt.Errorf("invalid field specifier length")
	}

	*data, fs.InformationElementID = (*data)[2:], binary.BigEndian.Uint16((*data)[:2])
	*data, fs.FieldLength = (*data)[2:], binary.BigEndian.Uint16((*data)[:2])

	// If the Enterprise bit is one, the Information Element identifier
	// identifies an enterprise-specific Information Element, and the Enterprise
	// Number field MUST be present.
	if fs.InformationElementID&EnterpriseBit > 0 {
		fs.EnterpriseBit = true
		fs.InformationElementID ^= EnterpriseBit
		// check length again as it depends if it is an entreprise field specifier
		if len(*data) < fs.Len()-4 {
			*data = []byte{}
			return fmt.Errorf("invalid enterprise number specifier length")
		}

		*data, fs.EnterpriseNumber = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	}
	return nil
}

// IPFIXDataSet is a set of Data Records (RFC 7011 section 3.3 and 3.4.3)
//
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |   Set ID = Template ID        |          Length               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |   Record 1 - Field Value 1    |   Record 1 - Field Value 2    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |   Record 1 - Field Value 3    |             ...               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |   Record 2 - Field Value 1    |   Record 2 - Field Value 2    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |   Record 2 - Field Value 3    |             ...               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |   Record 3 - Field Value 1    |   Record 3 - Field Value 2    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |   Record 3 - Field Value 3    |             ...               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |              ...              |      Padding (optional)       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IPFIXDataSet struct {
	// Set header
	Header IPFIXSetHeader
	// Data records in the set
	Records []IPFIXDataRecord
	// Raw bytes
	Bytes []byte
}

// Len returns the content length in octet of a Data Set
func (ds IPFIXDataSet) Len() int {
	return int(ds.Header.Length)
}

func (ds *IPFIXDataSet) decodeFromBytes(data *[]byte, t IPFIXTemplateAccessor) error {
	if len(*data) < ds.Len()-ds.Header.Len() {
		*data = []byte{}
		return fmt.Errorf("invalid data set length")
	}

	dataLen := ds.Len() - ds.Header.Len()
	// TODO: optimization, not store raw data if it was correctly decoded with
	//       the template
	ds.Bytes = (*data)[:dataLen]

	if t != nil {
		// a Data Set can contains multiple Data Records
		// we cannot know the exact length of a data record due to the variable
		// length of certain field but we know the minimum. So until we have
		// enough data for a record and we did not exceed the data set length,
		// we can decode another record.
		dataRead := 0
		for len(*data) >= int(t.GetMinDataRecordLength()) && dataRead < dataLen {
			dr := &IPFIXDataRecord{
				ID:     ds.Header.ID,
				Fields: []IPFIXField{},
			}
			n, err := dr.decodeFromBytes(data, t)
			if err != nil {
				return err
			}
			ds.Records = append(ds.Records, *dr)
			dataRead += n
		}

		// remaining octet corresponding to padding see RFC 7011 section 3.1.1
		padding := dataLen - dataRead
		if padding > 0 {
			for _, b := range (*data)[:padding] {
				if b != 0x00 {
					return fmt.Errorf("invalid data set padding value")
				}
			}
			*data = (*data)[padding:]
		}
	} else {
		*data = (*data)[dataLen:]
	}

	return nil
}

// DecodeWithTemplate decode Data Set's records with a given Template or Option
// Template
func (ds *IPFIXDataSet) DecodeWithTemplate(t IPFIXTemplateAccessor) error {
	return ds.decodeFromBytes(&ds.Bytes, t)
}

// IPFIXDataRecord is a Data Record (RFC 7011 section 3.4.3)
//
//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Record 1 - Field Value 1    |   Record 1 - Field Value 2    |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Record 1 - Field Value 3    |             ...               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Record 2 - Field Value 1    |   Record 2 - Field Value 2    |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Record 2 - Field Value 3    |             ...               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Record 3 - Field Value 1    |   Record 3 - Field Value 2    |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Record 3 - Field Value 3    |             ...               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |              ...              |      Padding (optional)       |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IPFIXDataRecord struct {
	// Template or Option template ID use to encode the record
	ID IPFIXSetIDType
	// List of fields in that template record.
	// Order matter as it respect the same order of Template Field Specifiers.
	Fields []IPFIXField
}

func (dr *IPFIXDataRecord) decodeFromBytes(data *[]byte, t IPFIXTemplateAccessor) (int, error) {
	dataRead := 0
	if t == nil {
		return dataRead, fmt.Errorf("cannot decode data record without a template record")
	}

	if dr.ID != t.GetID() {
		return dataRead, fmt.Errorf("invalid template ID")
	}

	if err := t.IterFieldSpecifier(func(fs *IPFIXFieldSpecifier) error {
		f := &IPFIXField{
			InformationElementID: fs.InformationElementID,
			EnterpriseNumber:     fs.EnterpriseNumber,
		}
		n, err := f.decodeFromBytes(data, fs)
		if err != nil {
			return err
		}
		dr.Fields = append(dr.Fields, *f)
		dataRead += n

		return nil
	}); err != nil {
		return dataRead, err
	}

	return dataRead, nil
}

// IPFIXField is a Field in a Data Record (RFC 7011 section 3.4.3)
//
//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Set ID = Template ID        |          Length               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Record 1 - Field Value 1    |   Record 1 - Field Value 2    |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Record 1 - Field Value 3    |             ...               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Record 2 - Field Value 1    |   Record 2 - Field Value 2    |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Record 2 - Field Value 3    |             ...               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Record 3 - Field Value 1    |   Record 3 - Field Value 2    |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |   Record 3 - Field Value 3    |             ...               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |              ...              |      Padding (optional)       |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IPFIXField struct {
	// A numeric value that represents the Information Element.  Refer to
	// [IANA-IPFIX].
	InformationElementID uint16
	// IANA enterprise number [IANA-PEN] of the authority defining the
	// Information Element identifier in this Template Record.
	EnterpriseNumber uint32
	Bytes            []byte
}

// Len returns the content length in octet of a Field
func (f IPFIXField) Len() int {
	return len(f.Bytes)
}

func (f *IPFIXField) decodeFromBytes(data *[]byte, fs *IPFIXFieldSpecifier) (int, error) {
	dataRead := 0
	if fs == nil {
		return dataRead, fmt.Errorf("cannot decode field without field specifier")
	}

	var length int
	if fs.FieldLength == VariableLength {
		// in variable length case, length is carried in the field content and
		// depending to the size, stored in the first byte or the 2 next for
		// optimization purpose. See RFC 7011 section 7.
		var l0 uint8
		var l1 uint16
		*data, l0 = (*data)[1:], (*data)[0]
		dataRead++
		if l0 == 0xff {
			*data, l1 = (*data)[2:], binary.BigEndian.Uint16((*data)[:2])
			dataRead += 2
			length = int(l1)
		} else {
			length = int(l0)
		}
	} else {
		length = int(fs.FieldLength)
	}

	if len(*data) < length {
		return dataRead, fmt.Errorf("invalid length field (got %d, expect %d)", len(*data), length)
	}

	f.EnterpriseNumber = fs.EnterpriseNumber
	f.InformationElementID = fs.InformationElementID
	*data, f.Bytes = (*data)[length:], (*data)[:length]
	dataRead += length

	return dataRead, nil
}
