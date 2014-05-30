// Copyright 2014 Laurent Hausermann <lh@hausermann.org>
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
	"encoding/binary"
	"fmt"
	"net"
)

type DNSClass uint16

const (
	DNSClassIN  DNSClass = 1   // Internet
	DNSClassCS  DNSClass = 2   // the CSNET class (Obsolete)
	DNSClassCH  DNSClass = 3   // the CHAOS class
	DNSClassHS  DNSClass = 4   // Hesiod [Dyer 87]
	DNSClassAny DNSClass = 255 // AnyClass
)

type DNSType uint16

const (
	DNSTypeA     DNSType = 1  // a host address
	DNSTypeNS    DNSType = 2  // an authoritative name server
	DNSTypeMD    DNSType = 3  // a mail destination (Obsolete - use MX)
	DNSTypeMF    DNSType = 4  // a mail forwarder (Obsolete - use MX)
	DNSTypeCNAME DNSType = 5  // the canonical name for an alias
	DNSTypeSOA   DNSType = 6  // marks the start of a zone of authority
	DNSTypeMB    DNSType = 7  // a mailbox domain name (EXPERIMENTAL)
	DNSTypeMG    DNSType = 8  // a mail group member (EXPERIMENTAL)
	DNSTypeMR    DNSType = 9  // a mail rename domain name (EXPERIMENTAL)
	DNSTypeNULL  DNSType = 10 // a null RR (EXPERIMENTAL)
	DNSTypeWKS   DNSType = 11 // a well known service description
	DNSTypePTR   DNSType = 12 // a domain name pointer
	DNSTypeHINFO DNSType = 13 // host information
	DNSTypeMINFO DNSType = 14 // mailbox or mail list information
	DNSTypeMX    DNSType = 15 // mail exchange
	DNSTypeTXT   DNSType = 16 // text strings
	DNSTypeAAAA  DNSType = 28 // a IPv6 host address [RFC3596]
	DNSTypeSRV   DNSType = 33 // server discovery [RFC2782] [RFC6195]
)

type DNSResponseCode uint8

const (
	DNSResponseCodeFormErr  DNSResponseCode = 1  // Format Error                       [RFC1035]
	DNSResponseCodeServFail DNSResponseCode = 2  // Server Failure                     [RFC1035]
	DNSResponseCodeNXDomain DNSResponseCode = 3  // Non-Existent Domain                [RFC1035]
	DNSResponseCodeNotImp   DNSResponseCode = 4  // Not Implemented                    [RFC1035]
	DNSResponseCodeRefused  DNSResponseCode = 5  // Query Refused                      [RFC1035]
	DNSResponseCodeYXDomain DNSResponseCode = 6  // Name Exists when it should not     [RFC2136]
	DNSResponseCodeYXRRSet  DNSResponseCode = 7  // RR Set Exists when it should not   [RFC2136]
	DNSResponseCodeNXRRSet  DNSResponseCode = 8  // RR Set that should exist does not  [RFC2136]
	DNSResponseCodeNotAuth  DNSResponseCode = 9  // Server Not Authoritative for zone  [RFC2136]
	DNSResponseCodeNotZone  DNSResponseCode = 10 // Name not contained in zone         [RFC2136]
	DNSResponseCodeBadVers  DNSResponseCode = 16 // Bad OPT Version                    [RFC2671]
	DNSResponseCodeBadSig   DNSResponseCode = 16 // TSIG Signature Failure             [RFC2845]
	DNSResponseCodeBadKey   DNSResponseCode = 17 // Key not recognized                 [RFC2845]
	DNSResponseCodeBadTime  DNSResponseCode = 18 // Signature out of time window       [RFC2845]
	DNSResponseCodeBadMode  DNSResponseCode = 19 // Bad TKEY Mode                      [RFC2930]
	DNSResponseCodeBadName  DNSResponseCode = 20 // Duplicate key name                 [RFC2930]
	DNSResponseCodeBadAlg   DNSResponseCode = 21 // Algorithm not supported            [RFC2930]
	DNSResponseCodeBadTruc  DNSResponseCode = 22 // Bad Truncation                     [RFC4635]
)

type DNSOpCode uint8

const (
	DNSOpCodeQuery  DNSOpCode = 0 // Query                  [RFC1035]
	DNSOpCodeIQuery DNSOpCode = 1 // Inverse Query Obsolete [RFC3425]
	DNSOpCodeStatus DNSOpCode = 2 // Status                 [RFC1035]
	DNSOpCodeNotify DNSOpCode = 4 // Notify                 [RFC1996]
	DNSOpCodeUpdate DNSOpCode = 5 // Update                 [RFC2136]
)

// DNS is specified in RFC 1034 / RFC 1035
// +---------------------+
// |        Header       |
// +---------------------+
// |       Question      | the question for the name server
// +---------------------+
// |        Answer       | RRs answering the question
// +---------------------+
// |      Authority      | RRs pointing toward an authority
// +---------------------+
// |      Additional     | RRs holding additional information
// +---------------------+
type DNS struct {
	BaseLayer
	Header      DNSHeader
	Questions   []DNSQuestion
	Answers     []DNSResourceRecord
	Authorities []DNSResourceRecord
	Additionals []DNSResourceRecord
}

// LayerType returns gopacket.LayerTypeDNS.
func (d *DNS) LayerType() gopacket.LayerType { return LayerTypeDNS }

// decodeDNS decodes the byte slice into a DNS type. It also
// setups the application Layer in PacketBuilder.
func decodeDNS(data []byte, p gopacket.PacketBuilder) error {
	d := &DNS{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)
	p.SetApplicationLayer(d)
	return nil
}

// DecodeFromBytes decodes the slice into the DNS struct.
func (d *DNS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	//TODO Check minimum len
	//TODO Review DPKT code
	//TODO Review Wireshark dissector code
	if err := d.Header.decode(data, df); err != nil {
		return err
	}

	offset := 12
	var err error
	for i := 0; i < int(d.Header.QDCount); i++ {
		q := DNSQuestion{}
		if offset, err = q.decode(data, offset, df); err != nil {
			return err
		}
		d.Questions = append(d.Questions, q)
	}

	for i := 0; i < int(d.Header.ANCount); i++ {
		a := DNSResourceRecord{}
		if offset, err = a.decode(data, offset, df); err != nil {
			return err
		}
		d.Answers = append(d.Answers, a)
	}

	for i := 0; i < int(d.Header.NSCount); i++ {
		a := DNSResourceRecord{}
		if offset, err = a.decode(data, offset, df); err != nil {
			return err
		}
		d.Authorities = append(d.Authorities, a)
	}

	for i := 0; i < int(d.Header.ARCount); i++ {
		a := DNSResourceRecord{}
		if offset, err = a.decode(data, offset, df); err != nil {
			return err
		}
		d.Additionals = append(d.Additionals, a)
	}

	return nil
}

func (d *DNS) CanDecode() gopacket.LayerClass {
	return LayerTypeDNS
}

func (d *DNS) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (d *DNS) Payload() []byte {
	return nil
}

//  DNS Header
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      ID                       |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    QDCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ANCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    NSCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ARCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSHeader is the header struct representing DNS headers
type DNSHeader struct {
	Id             uint16
	Qr             bool
	OpCode         DNSOpCode
	AA, TC, RD, RA bool
	Z              uint8
	ResponseCode   DNSResponseCode
	QDCount        uint16
	ANCount        uint16
	NSCount        uint16
	ARCount        uint16
}

// decode takes a []byte representing the data, and decode into the
// DNSHeader struct
func (h *DNSHeader) decode(data []byte, df gopacket.DecodeFeedback) error {
	h.Id = binary.BigEndian.Uint16(data[:2])
	h.Qr = data[2]>>7 != 0
	h.OpCode = DNSOpCode((data[2] >> 3) & 0xf)
	h.AA = (data[2] >> 2 & 0x1) != 0
	h.TC = (data[2] >> 1 & 0x1) != 0
	h.RD = (data[2] & 0x1) != 0
	h.RA = (data[3] >> 7 & 0x1) != 0
	h.Z = uint8(data[3] >> 4 & 0x7)
	h.ResponseCode = DNSResponseCode(data[3] & 0xf)
	h.QDCount = binary.BigEndian.Uint16(data[4:6])
	h.ANCount = binary.BigEndian.Uint16(data[6:8])
	h.NSCount = binary.BigEndian.Uint16(data[8:10])
	h.ARCount = binary.BigEndian.Uint16(data[10:12])

	return nil
}

func decodeName(data []byte, offset int) ([]byte, int, error) {
	name := make([]byte, 0, 16)

	index := offset
	for data[index] != 0x00 {
		switch data[index] & 0xc0 {
		default:
			/* RFC 1035
			   A domain name represented as a sequence of labels, where
			   each label consists of a length octet followed by that
			   number of octets.  The domain name terminates with the
			   zero length octet for the null label of the root.  Note
			   that this field may be an odd number of octets; no
			   padding is used.
			*/
			index2 := index + int(data[index]) + 1
			if index2-offset > 255 {
				return nil, 0,
					fmt.Errorf("dns name is too long")
			}
			name = append(name, '.')
			name = append(name, data[index+1:index2]...)
			index = index2

		case 0xc0:
			/* RFC 1035
			   The pointer takes the form of a two octet sequence.

			   The first two bits are ones.  This allows a pointer to
			   be distinguished from a label, since the label must
			   begin with two zero bits because labels are restricted
			   to 63 octets or less.  (The 10 and 01 combinations are
			   reserved for future use.)  The OFFSET field specifies
			   an offset from the start of the message (i.e., the
			   first octet of the ID field in the domain header).  A
			   zero offset specifies the first byte of the ID field,
			   etc.

			   The compression scheme allows a domain name in a message to be
			   represented as either:
			      - a sequence of labels ending in a zero octet
			      - a pointer
			      - a sequence of labels ending with a pointer
			*/

			offsetp := int(binary.BigEndian.Uint16(data[index:index+2]) & 0x3fff)
			namep, _, err := decodeName(data, offsetp)
			if err != nil {
				return nil, 0, err
			}
			name = append(name, '.')
			name = append(name, namep...)
			return name[1:], index + 2, nil

		/* EDNS, or other DNS option ? */
		case 0x40: // RFC 2673
			return nil, 0, fmt.Errorf("qname '0x40' unsupported yet (data=%x index=%d)",
				data[index], index)

		case 0x80:
			return nil, 0, fmt.Errorf("qname '0x80' unsupported yet (data=%x index=%d)",
				data[index], index)
		}
	}
	return name[1:], index + 1, nil
}

type DNSQuestion struct {
	Name  string
	Type  DNSType
	Class DNSClass
}

func (q *DNSQuestion) decode(data []byte, offset int, df gopacket.DecodeFeedback) (int, error) {
	name, endq, err := decodeName(data, offset)
	if err != nil {
		return 0, err
	}

	q.Name = string(name)
	q.Type = DNSType(binary.BigEndian.Uint16(data[endq : endq+2]))
	q.Class = DNSClass(binary.BigEndian.Uint16(data[endq+2 : endq+4]))

	return endq + 4, nil
}

//  DNSResourceRecord
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                                               |
//  /                                               /
//  /                      NAME                     /
//  |                                               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      TYPE                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                     CLASS                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      TTL                      |
//  |                                               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   RDLENGTH                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//  /                     RDATA                     /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type DNSResourceRecord struct {
	// Header
	Name  string
	Type  DNSType
	Class DNSClass
	TTL   uint32

	// RData Raw Values
	DataLength uint16
	Data       []byte

	// RDATA Decoded Values
	IP                  net.IP
	NS, CNAME, PTR, TXT string
	SOA                 DNSSOA
	SRV                 DNSSRV
	MX                  DNSMX
}

// decode decodes the resource record, returning the total length of the record.
func (rr *DNSResourceRecord) decode(data []byte, offset int, df gopacket.DecodeFeedback) (int, error) {
	name, endq, err := decodeName(data, offset)
	if err != nil {
		return 0, err
	}

	rr.Name = string(name)
	rr.Type = DNSType(binary.BigEndian.Uint16(data[endq : endq+2]))
	rr.Class = DNSClass(binary.BigEndian.Uint16(data[endq+2 : endq+4]))
	rr.TTL = binary.BigEndian.Uint32(data[endq+4 : endq+8])
	rr.DataLength = binary.BigEndian.Uint16(data[endq+8 : endq+10])
	rr.Data = data[endq+10 : endq+10+int(rr.DataLength)]

	if err = rr.decodeRData(data, endq+10); err != nil {
		return 0, err
	}

	return endq + 10 + int(rr.DataLength), nil
}

func (rr *DNSResourceRecord) String() string {
	if (rr.Class == DNSClassIN) && ((rr.Type == DNSTypeA) || (rr.Type == DNSTypeAAAA)) {
		return net.IP(rr.Data).String()
	}
	return "..."
}

func (rr *DNSResourceRecord) decodeRData(data []byte, offset int) error {
	switch rr.Type {
	case DNSTypeA:
		rr.IP = rr.Data
	case DNSTypeAAAA:
		rr.IP = rr.Data
	case DNSTypeTXT:
		rr.TXT = string(rr.Data)
	case DNSTypeHINFO:
		rr.TXT = string(rr.Data)
	case DNSTypeNS:
		name, _, err := decodeName(data, offset)
		if err != nil {
			return err
		}
		rr.NS = string(name)
	case DNSTypeCNAME:
		name, _, err := decodeName(data, offset)
		if err != nil {
			return err
		}
		rr.CNAME = string(name)
	case DNSTypePTR:
		name, _, err := decodeName(data, offset)
		if err != nil {
			return err
		}
		rr.PTR = string(name)
	case DNSTypeSOA:
		name, endq, err := decodeName(data, offset)
		if err != nil {
			return err
		}
		rr.SOA.MName = string(name)
		name, endq, err = decodeName(data, endq)
		if err != nil {
			return err
		}
		rr.SOA.RName = string(name)
		rr.SOA.Serial = binary.BigEndian.Uint32(data[endq : endq+4])
		rr.SOA.Refresh = binary.BigEndian.Uint32(data[endq+4 : endq+8])
		rr.SOA.Retry = binary.BigEndian.Uint32(data[endq+8 : endq+12])
		rr.SOA.Expire = binary.BigEndian.Uint32(data[endq+12 : endq+16])
		rr.SOA.Minimum = binary.BigEndian.Uint32(data[endq+16 : endq+20])
	case DNSTypeMX:
		rr.MX.Preference = binary.BigEndian.Uint16(data[offset : offset+2])
		name, _, err := decodeName(data, offset+2)
		if err != nil {
			return err
		}
		rr.MX.Name = string(name)
	case DNSTypeSRV:
		rr.SRV.Priority = binary.BigEndian.Uint16(data[offset : offset+2])
		rr.SRV.Weight = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		rr.SRV.Port = binary.BigEndian.Uint16(data[offset+4 : offset+6])
		name, _, err := decodeName(data, offset+6)
		if err != nil {
			return err
		}
		rr.SRV.Name = string(name)
	}
	return nil
}

type DNSSOA struct {
	MName, RName                            string
	Serial, Refresh, Retry, Expire, Minimum uint32
}

type DNSSRV struct {
	Priority, Weight, Port uint16
	Name                   string
}

type DNSMX struct {
	Preference uint16
	Name       string
}
