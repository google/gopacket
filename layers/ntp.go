//******************************************************************************
//
// Copyright 2016 Ross N. Williams. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
//
//******************************************************************************

package layers

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
)

//******************************************************************************
//
// Network Time Protocol (NTP) Decoding Layer
// ------------------------------------------
// This file provides a GoPacket decoding layer for NTP.
//
// More specifically, this file adds to the package "layers" an additional
// type called "NTP" that conforms to the interface type DecodingLayer
// that is defined in the package:
//
//    src/github.com/google/gopacket/parser.go
//
// To do this, it must implement the following functions:
//
//     DecodeFromBytes(data []byte, df DecodeFeedback) error
//     CanDecode() LayerClass
//     NextLayerType() LayerType
//     LayerPayload() []byte
//
//******************************************************************************
//
// About The Network Time Protocol (NTP)
// -------------------------------------
// NTP is a protocol that enables computers on the internet to set their
// clocks to the correct time (or to a time that is acceptably close to the
// correct time). NTP runs on top of UDP.
//
// There have been a series of versions of the NTP protocol. The latest
// version is V4 and is specified in RFC 5905:
//     http://www.ietf.org/rfc/rfc5905.txt
//
//******************************************************************************
//
// References
// ----------
//
// Wikipedia's NTP entry:
//     https://en.wikipedia.org/wiki/Network_Time_Protocol
//     This is the best place to get an overview of NTP.
//
// Network Time Protocol Home Website:
//     http://www.ntp.org/
//     This appears to be the official website of NTP.
//
// List of current NTP Protocol RFCs:
//     http://www.ntp.org/rfc.html
//
// RFC 958: "Network Time Protocol (NTP)" (1985)
//     https://tools.ietf.org/html/rfc958
//     This is the original NTP specification.
//
// RFC 1305: "Network Time Protocol (Version 3) Specification, Implementation and Analysis" (1992)
//     https://tools.ietf.org/html/rfc1305
//     The protocol was updated in 1992 yielding NTP V3.
//
// RFC 5905: "Network Time Protocol Version 4: Protocol and Algorithms Specification" (2010)
//     https://www.ietf.org/rfc/rfc5905.txt
//     The protocol was updated in 2010 yielding NTP V4.
//     V4 is backwards compatible with all previous versions of NTP.
//
// RFC 5906: "Network Time Protocol Version 4: Autokey Specification"
//     https://tools.ietf.org/html/rfc5906
//     This document addresses the security of the NTP protocol
//     and is probably not relevant to this package.
//
// RFC 5907: "Definitions of Managed Objects for Network Time Protocol Version 4 (NTPv4)"
//     https://tools.ietf.org/html/rfc5907
//     This document addresses the management of NTP servers and
//     is probably not relevant to this package.
//
// RFC 5908: "Network Time Protocol (NTP) Server Option for DHCPv6"
//     https://tools.ietf.org/html/rfc5908
//     This document addresses the use of NTP in DHCPv6 and is
//     probably not relevant to this package.
//
// "Let's make a NTP Client in C"
//     https://lettier.github.io/posts/2016-04-26-lets-make-a-ntp-client-in-c.html
//     This web page contains useful information about the details of NTP,
//     including an NTP record struture in C, and C code.
//
// "NTP Packet Header (NTP Reference Implementation) (Computer Network Time Synchronization)"
//     http://what-when-how.com/computer-network-time-synchronization/
//        ntp-packet-header-ntp-reference-implementation-computer-network-time-synchronization/
//     This web page contains useful information on the details of NTP.
//
// "Technical information - NTP Data Packet"
//     https://www.meinbergglobal.com/english/info/ntp-packet.htm
//     This page has a helpful diagram of an NTP V4 packet.
//
//******************************************************************************
//
// Obsolete References
// -------------------
//
// RFC 1119: "RFC-1119 "Network Time Protocol (Version 2) Specification and Implementation" (1989)
//     https://tools.ietf.org/html/rfc1119
//     Version 2 was drafted in 1989.
//     It is unclear whether V2 was ever implememented or whether the
//     ideas ended up in V3 (which was implemented in 1992).
//
// RFC 1361: "Simple Network Time Protocol (SNTP)"
//     https://tools.ietf.org/html/rfc1361
//     This document is obsoleted by RFC 1769 and is included only for completeness.
//
// RFC 1769: "Simple Network Time Protocol (SNTP)"
//     https://tools.ietf.org/html/rfc1769
//     This document is obsoleted by RFC 2030 and RFC 4330 and is included only for completeness.
//
// RFC 2030: "Simple Network Time Protocol (SNTP) Version 4 for IPv4, IPv6 and OSI"
//     https://tools.ietf.org/html/rfc2030
//     This document is obsoleted by RFC 4330 and is included only for completeness.
//
// RFC 4330: "Simple Network Time Protocol (SNTP) Version 4 for IPv4, IPv6 and OSI"
//     https://tools.ietf.org/html/rfc4330
//     This document is obsoleted by RFC 5905 and is included only for completeness.
//
//******************************************************************************
//
// Endian And Bit Numbering Issues
// -------------------------------
//
// Endian and bit numbering issues can be confusing. Here is some
// clarification:
//
//    ENDIAN: NTP uses "Network Byte Order" which is big-endian order. This
//    means that if a value contains (e.g.) four bytes, the most-significant
//    byte appears first and the least-significant byte appears last.
//    https://en.wikipedia.org/wiki/Endianness
//
//    BIT NUMBERING: Bits are numbered 0 upwards from the most significant
//    bit to the least significant bit. This means that if there is a 32-bit
//    value, the most significant bit is called bit 0 and the least
//    significant bit is called bit 31.
//
// RFC 791 (Internet Protocol) has a helpful Appendix B which describes
// the endian and bit numbering convention in internet protocols. It is
// reproduced here verbatim:
//
//    |APPENDIX B:  Data Transmission Order
//    |
//    |The order of transmission of the header and data described in this
//    |document is resolved to the octet level.  Whenever a diagram shows a
//    |group of octets, the order of transmission of those octets is the normal
//    |order in which they are read in English.  For example, in the following
//    |diagram the octets are transmitted in the order they are numbered.
//    |
//    |
//    |    0                   1                   2                   3
//    |    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+s
//    |   |       1       |       2       |       3       |       4       |
//    |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |   |       5       |       6       |       7       |       8       |
//    |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |   |       9       |      10       |      11       |      12       |
//    |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |
//    |                      Transmission Order of Bytes
//    |
//    |                               Figure 10.
//    |
//    |Whenever an octet represents a numeric quantity the left most bit in the
//    |diagram is the high order or most significant bit.  That is, the bit
//    |labeled 0 is the most significant bit.  For example, the following
//    |diagram represents the value 170 (decimal).
//    |
//    |
//    |                            0 1 2 3 4 5 6 7
//    |                           +-+-+-+-+-+-+-+-+
//    |                           |1 0 1 0 1 0 1 0|
//    |                           +-+-+-+-+-+-+-+-+
//    |
//    |                          Significance of Bits
//    |
//    |                               Figure 11.
//    |
//    |Similarly, whenever a multi-octet field represents a numeric quantity
//    |the left most bit of the whole field is the most significant bit.  When
//    |a multi-octet quantity is transmitted the most significant octet is
//    |transmitted first.
//    |https://tools.ietf.org/html/rfc791

//******************************************************************************
//
// NTP V3 and V4 Packet Format
// ---------------------------
// NTP packets are UDP packets whose payload contains an NTP record.
//
// The NTP RFC defines the format of the NTP record.
//
// There have been four versions of the protocol:
//
//    V1 in 1985
//    V2 in 1989
//    V3 in 1992
//    V4 in 2010
//
// It is clear that V1 and V2 are obsolete, and there is no need to
// cater for these formats.
//
// V3 and V4 essentially use the same format, with V4 adding some optional
// fields on the end. So this package supports the V3 and V4 formats.
//
// The current version of NTP (NTP V4)'s RFC (V4 - RFC 5905) contains
// the following diagram for the NTP record format:

//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                         Root Delay                            |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                         Root Dispersion                       |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                          Reference ID                         |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                                                               |
//     +                     Reference Timestamp (64)                  +
//     |                                                               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                                                               |
//     +                      Origin Timestamp (64)                    +
//     |                                                               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                                                               |
//     +                      Receive Timestamp (64)                   +
//     |                                                               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                                                               |
//     +                      Transmit Timestamp (64)                  +
//     |                                                               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                                                               |
//     .                                                               .
//     .                    Extension Field 1 (variable)               .
//     .                                                               .
//     |                                                               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                                                               |
//     .                                                               .
//     .                    Extension Field 2 (variable)               .
//     .                                                               .
//     |                                                               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                          Key Identifier                       |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                                                               |
//     |                            dgst (128)                         |
//     |                                                               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     From http://www.ietf.org/rfc/rfc5905.txt
//
// The fields "Extension Field 1 (variable)" and later are optional fields,
// and so we can set a minimum NTP record size of 48 bytes.
//
const ntp_minimum_record_size_in_bytes int = 48

//******************************************************************************

// NTP Type
// --------
// Type NTP implements the DecodingLayer interface. Each NTP object
// represents in a structured form the NTP record present as the UDP
// payload in an NTP UDP packet.
//
type NTP struct {
	BaseLayer // Stores the packet bytes and payload bytes.

	LeapIndicator uint8 // [0,3]. Indicates whether leap second(s) is to be added.
	Version       uint8 // [0,7]. Version of the NTP protocol.
	Mode          uint8 // [0,7]. Mode.
	Stratum       uint8 // [0,255]. Stratum of time server in the server tree.
	Poll          int8  // [-128,127]. The maximum interval between
	//             successive messages, in log2 seconds.
	Precision int8 // [-128,127]. The precision of the system clock,
	//             in log2 seconds.
	RootDelay uint32 // [0,2^32-1]. Total round trip delay to the reference clock
	//             in seconds times 2^16.
	RootDispersion uint32 // [0,2^32-1]. Total dispersion to the reference clock,
	//             in seconds times 2^16.
	ReferenceID        uint32 // ID code of reference clock [0,2^32-1].
	ReferenceTimestamp uint64 // Most recent timestamp from the reference clock.
	OriginTimestamp    uint64 // Local time when request was sent from local host.
	ReceiveTimestamp   uint64 // Local time (on server) that request arrived at server host.
	TransmitTimestamp  uint64 // Local time (on server) that request departed server host.

	// FIX: This package should analyse the extension fields and represent the extension fields too.
	ExtensionBytes []byte // Just put extensions in a byte slice.
}

//******************************************************************************

// LayerType() returns the layer type of the NTP object, which is LayerTypeNTP.
//
func (d *NTP) LayerType() gopacket.LayerType {
	return LayerTypeNTP
}

//******************************************************************************

// decodeNTP() analyses a byte slice and attempts to decode it as an NTP
// record of a UDP packet.
//
// If it succeeds, it loads p with information about the packet and returns nil.
// If it fails, it returns an error (non nil).
//
// This function is employed in layertypes.go to register the NTP layer.
//
func decodeNTP(data []byte, p gopacket.PacketBuilder) error {

	// Attempt to decode the byte slice.
	//
	d := &NTP{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	// If the decoding worked, add the layer to the packet and set it
	// as the application layer too, if there isn't already one.
	//
	p.AddLayer(d)
	p.SetApplicationLayer(d)

	return nil
}

//******************************************************************************

// decodeNTP() analyses a byte slice and attempts to decode it as an NTP
// record of a UDP packet.
//
// Upon succeeds, it loads the NTP object with information about the packet
// and returns nil.
// Upon failure, it returns an error (non nil).
//
func (d *NTP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	// If the data block is too short to be a NTP record, then return an error.
	//
	if len(data) < ntp_minimum_record_size_in_bytes {
		df.SetTruncated()
		return fmt.Errorf("NTP packet too short")
	}

	// RFC 5905 does not appear to define a maximum NTP record length.
	// The protocol allows "extension fields" to be included in the record,
	// and states about these fields:"
	//
	//     "While the minimum field length containing required fields is
	//      four words (16 octets), a maximum field length remains to be
	//      established."
	//
	// For this reason, the packet length is not checked here for being too long.

	// NTP type embeds type BaseLayer which contains two fields:
	//    Contents is supposed to contain the bytes of the data at this level.
	//    Payload is supposed to contain the payload of this level.
	// Here we set the baselayer to be the bytes of the NTP record.
	//
	d.BaseLayer = BaseLayer{Contents: data[:len(data)]}

	// Extract the fields from the block of bytes.
	// To make sense of this, refer to the packet diagram
	// above and the section on endian conventions.

	// The first few fields are all packed into the first 32 bits. Unpack them.
	f := binary.BigEndian.Uint32(data[0:4])
	d.LeapIndicator = uint8((f & 0xC0000000) >> 30)
	d.Version = uint8((f & 0x38000000) >> 27)
	d.Mode = uint8((f & 0x07000000) >> 24)
	d.Stratum = uint8((f & 0x00FF0000) >> 16)
	d.Poll = int8((f & 0x0000FF00) >> 8)
	d.Precision = int8((f & 0x000000FF) >> 0)

	// The remaining fields can just be copied in big endian order.
	d.RootDelay = binary.BigEndian.Uint32(data[4:8])
	d.RootDispersion = binary.BigEndian.Uint32(data[8:12])
	d.ReferenceID = binary.BigEndian.Uint32(data[12:16])
	d.ReferenceTimestamp = binary.BigEndian.Uint64(data[16:24])
	d.OriginTimestamp = binary.BigEndian.Uint64(data[24:32])
	d.ReceiveTimestamp = binary.BigEndian.Uint64(data[32:40])
	d.TransmitTimestamp = binary.BigEndian.Uint64(data[40:48])

	// This layer does not attempt to analyse the extension bytes.
	// But if there are any, we'd like the user to know. So we just
	// place them all in an ExtensionBytes field.
	d.ExtensionBytes = data[48:]

	// Return no error.
	return nil
}

//******************************************************************************

// CanDecode() returns a set of layers that NTP objects can decode.
// As NTP objects can only decide the NTP layer, we can return just that layer.
// Apparently a single layer type implements LayerClass.
//
func (d *NTP) CanDecode() gopacket.LayerClass {
	return LayerTypeNTP
}

//******************************************************************************

// NextLayerType() specifies the next layer that GoPacket should attempt to
// analyse after this (NTP) layer. As NTP packets do not contain any payload
// bytes, there are no further layers to analyse.
//
// FIX: What is the GoPacket convention here for indicating that no
//      further layers should be analysed? It seems inelegant to
//      specify that the Payload layer should be analysed next when
//      there is no payload.
//
func (d *NTP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

//******************************************************************************

// NTP packets do not carry any data payload, so the empty byte slice is retured.
// In Go, a nil slice is functionally identical to an empty slice, so we
// return nil to avoid a heap allocation.
//
func (d *NTP) Payload() []byte {
	return nil
}

//******************************************************************************
//*                            End Of NTP File                                 *
//******************************************************************************
