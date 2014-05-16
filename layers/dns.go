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

var (
	DNSClassIN  uint16 = 1   // Internet
	DNSClassCS  uint16 = 2   // the CSNET class (Obsolete)
	DNSClassCH  uint16 = 3   // the CHAOS class
	DNSClassHS  uint16 = 4   // Hesiod [Dyer 87]
	DNSClassAny uint16 = 255 // AnyClass
)

var (
	DNSTypeA     uint16 = 1  // a host address
	DNSTypeNS    uint16 = 2  // an authoritative name server
	DNSTypeMD    uint16 = 3  // a mail destination (Obsolete - use MX)
	DNSTypeMF    uint16 = 4  // a mail forwarder (Obsolete - use MX)
	DNSTypeCNAME uint16 = 5  // the canonical name for an alias
	DNSTypeSOA   uint16 = 6  // marks the start of a zone of authority
	DNSTypeMB    uint16 = 7  // a mailbox domain name (EXPERIMENTAL)
	DNSTypeMG    uint16 = 8  // a mail group member (EXPERIMENTAL)
	DNSTypeMR    uint16 = 9  // a mail rename domain name (EXPERIMENTAL)
	DNSTypeNULL  uint16 = 10 // a null RR (EXPERIMENTAL)
	DNSTypeWKS   uint16 = 11 // a well known service description
	DNSTypePTR   uint16 = 12 // a domain name pointer
	DNSTypeHINFO uint16 = 13 // host information
	DNSTypeMINFO uint16 = 14 // mailbox or mail list information
	DNSTypeMX    uint16 = 15 // mail exchange
	DNSTypeTXT   uint16 = 16 // text strings
	DNSTypeAAAA  uint16 = 28 // a IPv6 host address [RFC3596]
	DNSTypeSRV   uint16 = 33 // server discovery [RFC2782] [RFC6195]
)

var (
	DNSRCodeFormErr  uint8 = 1  // Format Error                       [RFC1035]
	DNSRCodeServFail uint8 = 2  // Server Failure                     [RFC1035]
	DNSRCodeNXDomain uint8 = 3  // Non-Existent Domain                [RFC1035]
	DNSRCodeNotImp   uint8 = 4  // Not Implemented                    [RFC1035]
	DNSRCodeRefused  uint8 = 5  // Query Refused                      [RFC1035]
	DNSRCodeYXDomain uint8 = 6  // Name Exists when it should not     [RFC2136]
	DNSRCodeYXRRSet  uint8 = 7  // RR Set Exists when it should not   [RFC2136]
	DNSRCodeNXRRSet  uint8 = 8  // RR Set that should exist does not  [RFC2136]
	DNSRCodeNotAuth  uint8 = 9  // Server Not Authoritative for zone  [RFC2136]
	DNSRCodeNotZone  uint8 = 10 // Name not contained in zone         [RFC2136]
	DNSRCodeBadVers  uint8 = 16 // Bad OPT Version                    [RFC2671]
	DNSRCodeBadSig   uint8 = 16 // TSIG Signature Failure             [RFC2845]
	DNSRCodeBadKey   uint8 = 17 // Key not recognized                 [RFC2845]
	DNSRCodeBadTime  uint8 = 18 // Signature out of time window       [RFC2845]
	DNSRCodeBadMode  uint8 = 19 // Bad TKEY Mode                      [RFC2930]
	DNSRCodeBadName  uint8 = 20 // Duplicate key name                 [RFC2930]
	DNSRCodeBadAlg   uint8 = 21 // Algorithm not supported            [RFC2930]
	DNSRCodeBadTruc  uint8 = 22 // Bad Truncation                     [RFC4635]
)

var (
	DNSOpCodeQuery  uint8 = 0 // Query                  [RFC1035]
	DNSOpCodeIQuery uint8 = 1 // Inverse Query Obsolete [RFC3425]
	DNSOpCodeStatus uint8 = 2 // Status                 [RFC1035]
	DNSOpCodeNotify uint8 = 4 // Notify                 [RFC1996]
	DNSOpCodeUpdate uint8 = 5 // Update                 [RFC2136]
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
	Answers     []DNSRR
	Authorities []DNSRR
	Additionals []DNSRR
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
	err := d.Header.decode(data, df)
	if err != nil {
		return err
	}

	offset := 12
	for nq := 0; nq < int(d.Header.QDCount); nq = nq + 1 {
		q := DNSQuestion{}
		err, ql := q.decode(data, offset, df)
		if err != nil {
			return err
		}
		d.Questions = append(d.Questions, q)
		offset = ql
	}

	for na := 0; na < int(d.Header.ANCount); na = na + 1 {
		a := DNSRR{}
		err, al := a.decode(data, offset, df)
		if err != nil {
			return err
		}
		d.Answers = append(d.Answers, a)
		offset = al
	}

	for ns := 0; ns < int(d.Header.NSCount); ns = ns + 1 {
		a := DNSRR{}
		err, al := a.decode(data, offset, df)
		if err != nil {
			return err
		}
		d.Authorities = append(d.Authorities, a)
		offset = al
	}

	for ar := 0; ar < int(d.Header.ARCount); ar = ar + 1 {
		a := DNSRR{}
		err, al := a.decode(data, offset, df)
		if err != nil {
			return err
		}
		d.Additionals = append(d.Additionals, a)
		offset = al
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
	//TODO Fixme, I should serialize here
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
	OpCode         uint8
	AA, TC, RD, RA bool
	Z              uint8
	RCode          uint8
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
	h.OpCode = uint8((data[2] >> 3) & 0xf)
	h.AA = (data[2] >> 2 & 0x1) != 0
	h.TC = (data[2] >> 1 & 0x1) != 0
	h.RD = (data[2] & 0x1) != 0
	h.RA = (data[3] >> 7 & 0x1) != 0
	h.Z = uint8(data[3] >> 4 & 0x7)
	h.RCode = uint8(data[3] & 0xf)
	h.QDCount = binary.BigEndian.Uint16(data[4:6])
	h.ANCount = binary.BigEndian.Uint16(data[6:8])
	h.NSCount = binary.BigEndian.Uint16(data[8:10])
	h.ARCount = binary.BigEndian.Uint16(data[10:12])

	return nil
}

func decodeName(data []byte, offset int) (string, int, error) {
	var name string

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
				return "", 0,
					fmt.Errorf("dns name is too long")
			}
			name = name + "." + string(data[index+1:index2])
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
				return "", 0, err
			}
			name = name + "." + namep
			return name[1:], index + 2, nil

		/* EDNS, or other DNS option ? */
		case 0x40: // RFC 2673
			return "", 0, fmt.Errorf("qname '0x40' unsupported yet (data=%x index=%d)",
				data[index], index)

		case 0x80:
			return "", 0, fmt.Errorf("qname '0x80' unsupported yet (data=%x index=%d)",
				data[index], index)
		}
	}
	return name[1:], index + 1, nil
}

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

func (q *DNSQuestion) decode(data []byte, offset int, df gopacket.DecodeFeedback) (error, int) {
	name, endq, err := decodeName(data, offset)
	if err != nil {
		return err, 0
	}

	q.Name = name
	q.Type = binary.BigEndian.Uint16(data[endq : endq+2])
	q.Class = binary.BigEndian.Uint16(data[endq+2 : endq+4])

	return nil, endq + 4
}

//  DNSRR
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

type DNSRR struct {
	// Header
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32

	// RData Raw Values
	rdlength uint16
	rdata    []byte

	// RDATA Decoded Values
	IP                  net.IP
	NS, CNAME, PTR, TXT string
	SOA                 DNSSOA
	SRV                 DNSSRV
	MX                  DNSMX
}

func (rr *DNSRR) decode(data []byte, offset int, df gopacket.DecodeFeedback) (error, int) {
	name, endq, err := decodeName(data, offset)
	if err != nil {
		return err, 0
	}

	rr.Name = name
	rr.Type = binary.BigEndian.Uint16(data[endq : endq+2])
	rr.Class = binary.BigEndian.Uint16(data[endq+2 : endq+4])
	rr.TTL = binary.BigEndian.Uint32(data[endq+4 : endq+8])
	rr.rdlength = binary.BigEndian.Uint16(data[endq+8 : endq+10])
	rr.rdata = data[endq+10 : endq+10+int(rr.rdlength)]

	err = rr.decodeRData(data, endq+10)
	if err != nil {
		return err, 0
	}

	return nil, endq + 10 + int(rr.rdlength)
}

func (rr *DNSRR) String() string {
	if (rr.Class == DNSClassIN) && ((rr.Type == DNSTypeA) || (rr.Type == DNSTypeAAAA)) {
		return net.IP(rr.rdata).String()
	}
	return "..."
}

func (rr *DNSRR) decodeRData(data []byte, offset int) error {
	switch rr.Type {

	case DNSTypeA:
		rr.IP = rr.rdata

	case DNSTypeAAAA:
		rr.IP = rr.rdata

	case DNSTypeTXT:
		rr.TXT = string(rr.rdata)

	case DNSTypeHINFO:
		rr.TXT = string(rr.rdata)

	case DNSTypeNS:
		name, _, err := decodeName(data, offset)
		if err != nil {
			return err
		}
		rr.NS = name

	case DNSTypeCNAME:
		name, _, err := decodeName(data, offset)
		if err != nil {
			return err
		}
		rr.CNAME = name

	case DNSTypePTR:
		name, _, err := decodeName(data, offset)
		if err != nil {
			return err
		}
		rr.PTR = name

	case DNSTypeSOA:
		name, endq, err := decodeName(data, offset)
		if err != nil {
			return err
		}
		rr.SOA.MName = name
		name, endq, err = decodeName(data, endq)
		if err != nil {
			return err
		}
		rr.SOA.RName = name
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
		rr.MX.Name = name

	case DNSTypeSRV:
		rr.SRV.Priority = binary.BigEndian.Uint16(data[offset : offset+2])
		rr.SRV.Weight = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		rr.SRV.Port = binary.BigEndian.Uint16(data[offset+4 : offset+6])
		name, _, err := decodeName(data, offset+6)
		if err != nil {
			return err
		}
		rr.SRV.Name = name

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
