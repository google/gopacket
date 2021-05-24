package layers

import (
	"fmt"
	"io"

	"github.com/google/gopacket"
)

const (
	// gtpV1UType is a GTPv1 Message Type for T-PDU, i.e.
	// GTPv1-U.
	gtpV1UType uint8 = 255
)

// indexed by GTPv1 IE type
// please refer to 3GPP TS 29.060 for Information Elements length.
//
// 3GPP TS 29060, 7.7.0:
//   ...
//   The most significant bit in the Type field is set to 0 when the
//   TV format is used and set to 1 for the TLV format.
//
// Hence IE types <128 have hardcoded length.
var gtpV1IELen = [128]uint8{
	1:   1,  // "Cause"
	2:   8,  // "International Mobile Subscriber Identity (IMSI)"
	3:   6,  // "Routeing Area Identity (RAI)"
	4:   4,  // "Temporary Logical Link Identity (TLLI)"
	5:   4,  // "Packet TMSI (P-TMSI)"
	6:   3,  // "Quality of Service"
	8:   1,  // "Reordering Required"
	9:   28, // "Authentication Triplet"
	11:  1,  // "MAP Cause"
	12:  3,  // "P-TMSI Signature"
	13:  1,  // "MS Validated"
	14:  1,  // "Recovery"
	15:  1,  // "Selection Mode"
	16:  4,  // "Tunnel Endpoint Identifier Data I"
	17:  4,  // "Tunnel Endpoint Identifier Control Plane"
	18:  5,  // "Tunnel Endpoint Identifier Data II"
	19:  1,  // "Teardown Ind"
	20:  1,  // "NSAPI"
	21:  1,  // "RANAP Cause"
	22:  9,  // "RAB Context"
	23:  1,  // "Radio Priority SMS"
	24:  1,  // "Radio Priority"
	25:  2,  // "Packet Flow Id"
	26:  2,  // "Charging Characteristics"
	27:  2,  // "Trace Reference"
	28:  2,  // "Trace Type"
	29:  1,  // "MS Not Reachable Reason"
	126: 1,  // "Packet Transfer Command", 3GPP TS 32.395
	127: 4,  // "Charging ID"
}

// indexed by GTPv2 IE type
// please refer to 3GPP TS 29.274 to identify Grouped IE types.
var gtpV2GroupedIE = [256]bool{
	93:  true, // "Bearer Context"
	109: true, // "PDN Connection"
	180: true, // "Overload Control Information"
	181: true, // "Load Control Information"
	191: true, // "Remote UE Context"
	195: true, // "SCEF PDN Connection"
}

var (
	// ErrGTPInvalidLength is returned when parsing GTP stumbles upon
	// insufficient amount of data.
	ErrGTPInvalidLength = fmt.Errorf("GTP invalid field length")
)

// ErrGTPUnknownIE is returned if the IE is impossible to parse.
type ErrGTPUnknownIE struct {
	Version, Type uint8
}

func (e ErrGTPUnknownIE) Error() string {
	return fmt.Sprintf("unparseable GTPv%d IE, type=%d", e.Version, e.Type)
}

// ErrGTPVersion means GTP Header contains unsupported version.
type ErrGTPVersion struct {
	Version uint8
}

func (e ErrGTPVersion) Error() string {
	return fmt.Sprintf("unsupported GTP version: %v", e.Version)
}

// GTPInformationElement describes GTP Information Element.
type GTPInformationElement struct {
	// Information Element type. Valid for GTPv1-C and GTPv2-C.
	Type uint8

	// Instance 4-bit field value. It's present in GTPv2 Information
	// Element format only and its value is described per each IE in
	// 3GPP TS 29.274.
	Instance uint8

	// GTPv2 Information Element may be "grouped", i.e. represent a
	// list of other Information Elements.
	//
	// If true, nested Information Elements are in
	// InformationElements.
	IsGrouped bool

	// Encoded Information Element data.
	Content []byte

	// Information Elements contained in this IE if IsGrouped is true.
	InformationElements []GTPInformationElement
}

// GTP represents GTPv1/v2 protocol layer.
type GTP struct {
	BaseLayer

	// Version field: This field is used to determine the version of
	// the GTP protocol.
	Version uint8

	// Message type represents a type of GTP message.
	//
	// Valid message type values are listed in 3GPP TS 29.060, clause
	// 7.1 for GTPv1 and in 3GPP TS 29.274, Table 6.1-1 for GTPv2.
	Type uint8

	// SequenceNumber of the GTP message. Use to match triggered
	// messages on GTP entities.
	//
	// In GTPv1-C it is 16 bit, GTPv2-C it is 24 bit.
	SequenceNumber uint32

	// Tunnel Endpoint Identifier field.
	//
	// Tunnel Endpoint Identifier (TEID): This field unambiguously
	// identifies a tunnel endpoint in the receiving GTP-U or GTP-C
	// protocol entity.
	//
	// TEID has 32 bits in both GTPv1 and GTPv2.
	TEID uint32

	// V1 contains GTPv1-C specific header fields.
	V1 struct {
		// Protocol Type (PT): This bit is used as a protocol
		// discriminator between GTP (when PT is "1") and GTP' (when PT is
		// "0"). GTP is described in this document and the GTP' protocol
		// in 3GPP TS 32.295 [33]. Note that the interpretation of the
		// header fields may be different in GTP' than in GTP.
		ProtocolType uint8

		// Extension Header flag (E): This flag indicates the presence of
		// a meaningful value of the Next Extension Header field. When it
		// is set to "0", the Next Extension Header field either is not
		// present or, if present, shall not be interpreted.  When it is
		// set to "1", the Next Extension Header field is present, and
		// shall be interpreted, as described below in this clause.
		IsExtensionHeader bool

		// Sequence number flag (S): This flag indicates the presence of a
		// meaningful value of the Sequence Number field. When it is set
		// to "0", the Sequence Number field either is not present or, if
		// present, shall not be interpreted. When it is set to "1", the
		// Sequence Number field is present, and shall be interpreted, as
		// described below in this clause.
		IsSequenceNumber bool

		// N-PDU Number flag (PN): This flag indicates the presence of a
		// meaningful value of the N-PDU Number field. When it is set to
		// "0", the N-PDU Number field either is not present, or, if
		// present, shall not be interpreted. When it is set to "1", the
		// N-PDU Number field is present, and shall be interpreted, as
		// described below in this clause.
		IsNPDU bool

		// N-PDU Number: This field is used at the Inter SGSN Routeing
		// Area Update procedure and some inter-system handover procedures
		// (e.g. between 2G and 3G radio access networks). This field is
		// used to co-ordinate the data transmission for acknowledged mode
		// of communication between the MS and the SGSN. The exact meaning
		// of this field depends upon the scenario. (For example, for
		// GSM/GPRS to GSM/GPRS, the SNDCP N-PDU number is present in this
		// field).
		NPDU uint8

		// Extensions includes all GTPv1-C extensions starting from Next
		// Extension Header Type.
		//
		// Extensions are only in GTPv1-C because they are not a part of
		// GTPv2-C, as stated in 3GPP TS 29.274, clause 5.2:
		//
		//   The legacy Extension Header mechanism is not used for the GTP
		//   version 2 control plane (GTPv2-C). Future extensions will be
		//   implemented by adding Information Elements in the message
		//   body if new parameters are needed.
		ExtensionHeaders []GTPExtensionHeader
	}

	// V2 contains GTPv2-C specific header fields.
	V2 struct {
		// Bit 5 represents a "P" flag. If the "P" flag is set to "0", no
		// piggybacked message shall be present. If the "P" flag is set to
		// "1", then another GTPv2-C message with its own header and body
		// shall be present at the end of the current message.
		//
		// When present, a piggybacked message shall have its "P" flag set
		// to "0" in its own header. If a Create Session Response message
		// (as part of EUTRAN initial attach, a Handover from Trusted or
		// Untrusted Non-3GPP IP Access to E-UTRAN (see clauses 8.6 and
		// 16.11 of 3GPP TS 23.402 [45]) or UE-requested PDN connectivity
		// procedure) has the "P" flag set to "1", then a single Create
		// Bearer Request message shall be present as the piggybacked
		// message. As a response to the Create Bearer Request message, if
		// the Create Bearer Response has the "P" flag set to "1", then a
		// single Modify Bearer Request (as part of EUTRAN initial attach,
		// a Handover from Trusted or Untrusted Non-3GPP IP Access to
		// E-UTRAN (see clauses 8.6 and 16.11 of 3GPP TS 23.402 [45]) or
		// UE-requested PDN connectivity procedure) shall be present as
		// the piggybacked message. A Create Bearer Response with "P" flag
		// set to "1" shall not be sent unless a Create Session Response
		// with "P" flag set to "1" has been received for the same
		// procedure. Apart from Create Session Response and Create Bearer
		// Response messages, all the EPC specific messages shall have the
		// "P" flag set to "0".
		IsPiggyback bool

		// Bit 4 represents a "T" flag, which indicates if TEID field
		// is present in the GTP-C header or not. If the "T" flag is set
		// to 0, then the TEID field shall not be present in the GTP-C
		// header. If the "T" flag is set to 1, then the TEID field shall
		// immediately follow the Length field, in octets 5 to 8. Apart
		// from the Echo Request, Echo Response and Version Not Supported
		// Indication messages, in all EPC specific messages the value of
		// the "T" flag shall be set to "1".
		IsTEID bool

		// Bit 3  represents a "MP" flag. If the "MP" flag is set to "1",
		// then bits 8 to 5 of octet 12 shall indicate the message
		// priority.
		IsMsgPrio bool

		// Bits 8 to 5 of octet 12 shall indicate the relative priority of
		// the GTP-C message, if the "MP" flag is set to 1 in Octet 1. It
		// shall be encoded as the binary value of the Message Priority
		// and it may take any value between 0 and 15, where 0 corresponds
		// to the highest priority and 15 the lowest priority.
		//
		// If the "MP" flag is set to "0" in Octet 1, bits 8 to 5 of octet
		// 12 shall be set to "0" by the sending entity and ignored by the
		// receiving entity.
		MsgPrio uint8
	}

	// Information Elements.
	InformationElements []GTPInformationElement

	// Information Elements plain buffer
	ieBuf []GTPInformationElement
}

func decodeGTP(data []byte, p gopacket.PacketBuilder) error {
	m := &GTP{}
	if err := m.DecodeFromBytes(data, p); err != nil {
		return err
	}

	p.AddLayer(m)
	return p.NextDecoder(m.NextLayerType())
}

// decode GTPv1-C Header Extension, specify data to decode, Next
// Extension Type and array to append extension headers to.  Return
// amount of consumed bytes and true if decoding was successful.
func decodeExtensions(data []byte, nextType uint8, pExts *[]GTPExtensionHeader) (n int, ok bool) {
	exts := (*pExts)[:0]

	var ext GTPExtensionHeader
	var length uint8

	for nextType != 0 {
		ext.Type = nextType

		if data, ok = ReadUint8(data, &length); !ok || length == 0 {
			return n, false
		}

		d := 4 * int(length)
		// content length, except for length (-1) and nextType (-1)
		data, ok = ReadBytes(data, &ext.Content, d-2)
		if data, ok = ReadUint8(data, &nextType); !ok {
			return n, false
		}

		n += d
		exts = append(exts, ext)
	}

	*pExts = exts
	return
}

// data must have at least 1 byte.
func (m *GTP) decodeGTPv1(data []byte, df gopacket.DecodeFeedback) error {
	// The GTP header is a variable length header used for both the
	// GTP-C and the GTP-U protocols. The minimum length of the GTP
	// header is 8 bytes.
	//
	// There are three flags that are used to signal the presence of
	// additional optional fields: the PN flag, the S flag and the E
	// flag.  The PN flag is used to signal the presence of N-PDU
	// Numbers. The S flag is used to signal the presence of the GTP
	// Sequence Number field. The E flag is used to signal the
	// presence of the Extension Header field, used to enable future
	// extensions of the GTP header defined in this document, without
	// the need to use another version number.
	//
	// If and only if one or more of these three flags are set, the
	// fields Sequence Number, N-PDU and Extension Header shall be
	// present.  The sender shall set all the bits of the unused
	// fields to zero. The receiver shall not evaluate the unused
	// fields.
	var flags uint8
	var length uint16
	origData := data

	// read mandatory part
	data, ok := ReadUint8(data, &flags)
	data, ok = ReadUint8(data, &m.Type)
	data, ok = BeReadUint16(data, &length)
	if data, ok = BeReadUint32(data, &m.TEID); !ok {
		df.SetTruncated()
		return io.ErrUnexpectedEOF
	}

	// consumed bytes
	n := 8

	// finished mandatory part of the message
	if len(data) < int(length) {
		// we've got less data than specified in the packet.
		df.SetTruncated()
		return io.ErrUnexpectedEOF
	}

	// truncate data.
	data = data[:length]

	// dissect flags
	m.V1.ProtocolType = (flags & 0x10) >> 4
	m.V1.IsExtensionHeader = (flags & 0x4) != 0 // E
	m.V1.IsSequenceNumber = (flags & 0x2) != 0  // S
	m.V1.IsNPDU = (flags & 0x1) != 0            // PN
	m.V1.ExtensionHeaders = m.V1.ExtensionHeaders[:0]

	// if any of PN, S, E are set all these fields are present.
	if (flags & 0x7) != 0 {
		// whether these fields are evaluated or not, we consume
		// them because they are present.
		var nextType uint8
		var k uint16
		data, ok = BeReadUint16(data, &k)
		data, ok = ReadUint8(data, &m.V1.NPDU)
		if data, ok = ReadUint8(data, &nextType); !ok {
			return ErrGTPInvalidLength
		}

		m.SequenceNumber = uint32(k)
		n += 4

		if pExts := &m.V1.ExtensionHeaders; m.V1.IsExtensionHeader {
			k, ok := decodeExtensions(data, nextType, pExts)
			if !ok {
				return ErrGTPInvalidLength
			}
			data = data[k:]
			n += k
		}
	} else {
		m.SequenceNumber = 0
		m.V1.NPDU = 0
	}

	if m.Type == gtpV1UType {
		// GTPv1-U, the Payload must be IPv4/v6 packet.
		m.Contents = origData[:n]
		m.InformationElements = nil
		m.Payload = data
		return nil
	}

	// GTPv1-C, no payload.
	m.Contents = origData
	m.Payload = nil
	return m.parseIEv1(data)
}

// data must have at least 1 byte.
func (m *GTP) decodeGTPv2(data []byte, df gopacket.DecodeFeedback) error {
	origData := data

	var flags uint8
	var length uint16

	// read mandatory part
	data, ok := ReadUint8(data, &flags)
	data, ok = ReadUint8(data, &m.Type)

	if data, ok = BeReadUint16(data, &length); !ok {
		df.SetTruncated()
		return io.ErrUnexpectedEOF
	}

	// finished mandatory part of the message
	if len(data) < int(length) {
		df.SetTruncated()
		return io.ErrUnexpectedEOF
	}

	m.Payload = data[length:]

	// we consumed 4 bytes so far
	m.Contents = origData[:4+int(length)]

	data = data[:length]

	m.V2.IsPiggyback = (flags & 0x10) != 0
	m.V2.IsMsgPrio = (flags & 0x4) != 0

	if m.V2.IsTEID = (flags & 0x8) != 0; m.V2.IsTEID {
		data, ok = BeReadUint32(data, &m.TEID)
	}

	if data, ok = BeReadUint32(data, &m.SequenceNumber); !ok {
		return ErrGTPInvalidLength
	}

	m.V2.MsgPrio = uint8((m.SequenceNumber & 0xf0) >> 4)
	m.SequenceNumber >>= 8

	return m.parseIEv2(data)
}

// DecodeFromBytes implements gopacket.DecodingLayer interface.
func (m *GTP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) == 0 {
		return ErrGTPInvalidLength
	}

	flags := data[0]

	switch m.Version = (flags & 0xE0) >> 5; m.Version {
	case 1:
		return m.decodeGTPv1(data, df)
	case 2:
		return m.decodeGTPv2(data, df)
	}

	return ErrGTPVersion{m.Version}
}

// NextLayerType implements gopacket.DecodingLayer interface.
//
// GTPv1-U may contain IP packet and GTPv2-C may contain 'piggybacked'
// packet of the same protocol. Otherwise, no payload should be
// contained.
func (m *GTP) NextLayerType() gopacket.LayerType {
	payload := m.LayerPayload()

	if len(payload) == 0 {
		// GTP-C, either v1 or v2, no payload
		return gopacket.LayerTypeZero
	}

	if m.Version == 2 {
		if m.V2.IsPiggyback {
			// GTPv2-C, piggybacking
			return LayerTypeGTP
		}
		return gopacket.LayerTypeZero
	}

	if m.Type != gtpV1UType {
		// GTPv1-C
		return gopacket.LayerTypeZero
	}

	// GTPv1-U
	switch payload[0] >> 4 {
	case 4:
		return LayerTypeIPv4
	case 6:
		return LayerTypeIPv6
	default:
		return LayerTypePPP
	}
}

// LayerType implements gopacket.Layer interface.
func (m *GTP) LayerType() gopacket.LayerType {
	return LayerTypeGTP
}

// CanDecode implements gopacket.DecodingLayer interface.
//
// This decoding layer can decode both LayerTypeGTP and
// LayerTypeGTPv1U.
func (m *GTP) CanDecode() gopacket.LayerClass {
	return gopacket.NewLayerClass([]gopacket.LayerType{
		LayerTypeGTP,
		LayerTypeGTPv1U,
	})
}

// 3GPP TS 29060, 7.7.0:
//
//   A GTP Signalling message may contain several information
//   elements.  The TLV (Type, Length, Value) or TV (Type, Value)
//   encoding format shall be used for the GTP information elements.
//   The information elements shall be sorted, with the Type fields in
//   ascending order, in the signalling messages. The Length field
//   contains the length of the information element excluding the Type
//   and Length field.
//   ...
//   The most significant bit in the Type field is set to 0 when the
//   TV format is used and set to 1 for the TLV format.
func gtpParseIEv1(data []byte, p *[]GTPInformationElement) (err error) {
	var ok bool
	var ie GTPInformationElement
	var length uint16
	e := ErrGTPUnknownIE{Version: 1}

	for len(data) > 0 {
		if data, _ = ReadUint8(data, &ie.Type); ie.Type < 0x80 {
			length = uint16(gtpV1IELen[ie.Type])
		} else if data, ok = BeReadUint16(data, &length); !ok {
			e.Type = ie.Type
			return e
		}

		if length == 0 {
			e.Type = ie.Type
			return e
		}

		if data, ok = ReadBytes(data, &ie.Content, int(length)); !ok {
			e.Type = ie.Type
			return e
		}

		*p = append(*p, ie)
	}

	return
}

// 3GPP TS 29.274, clause 8.0
//
//   A GTP control plane (signalling) message may contain several
//   information elements. In order to have forward compatible type
//   definitions for the GTPv2 information elements, all of them shall be
//   TLIV (Type, Length, Instance, Value) coded.
func gtpParseIEv2(data []byte, p *[]GTPInformationElement) (err error) {
	var ie GTPInformationElement
	var length uint16
	var ok bool
	e := ErrGTPUnknownIE{Version: 2}

	for len(data) > 0 {
		data, _ = ReadUint8(data, &ie.Type)
		data, _ = BeReadUint16(data, &length)
		if data, ok = ReadUint8(data, &ie.Instance); !ok {
			e.Type = ie.Type
			return e
		}

		if data, ok = ReadBytes(data, &ie.Content, int(length)); !ok {
			e.Type = ie.Type
			return e
		}

		ie.Instance &= 0xf
		ie.IsGrouped = gtpV2GroupedIE[ie.Type]
		*p = append(*p, ie)
	}

	return
}

func (m *GTP) parseIEv2Recurse(data []byte, p *[]GTPInformationElement) error {
	n := len(m.ieBuf)
	if err := gtpParseIEv2(data, &m.ieBuf); err != nil {
		return err
	}

	ies := m.ieBuf[n:]

	for i := range ies {
		if ie := &ies[i]; ie.IsGrouped {
			if err := m.parseIEv2Recurse(ie.Content, &ie.InformationElements); err != nil {
				return err
			}
		}
	}

	*p = ies
	return nil
}

// parseIEv1 parses InformationElements for GTPv1-C.
func (m *GTP) parseIEv1(data []byte) error {
	m.ieBuf = m.ieBuf[:0]
	err := gtpParseIEv1(data, &m.ieBuf)
	m.InformationElements = m.ieBuf
	return err
}

// parseIEv2 parses InformationElements for GTPv2-C.
func (m *GTP) parseIEv2(data []byte) error {
	m.ieBuf = m.ieBuf[:0]
	return m.parseIEv2Recurse(data, &m.InformationElements)
}
