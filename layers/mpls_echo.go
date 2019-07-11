// Copyright 2018 GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket" // BSD license
	"net"
)

// This file implements a layer that enables Label Switched Path (LSP) Ping/Traceroute operations to be conducted
// inside Multiprotocol Label Switching (MPLS) networks for data plane failure detection and localization, per RFC8029.

// MPLSEchoVersion is used to express the MPLS Echo protocol version being used. The version is to be incremented whenever
// a change is made that affects the ability of an implementation to correctly parse or process an MPLS echo request/reply.
type MPLSEchoVersion uint16

const (
	// MPLSEchoVersion1 is the first version of the MPLS Echo protocol.
	MPLSEchoVersion1 MPLSEchoVersion = iota + 1
)

// MPLSEchoGlobalFlags is a bitmask type that represents an MPLS echo request/reply's global flags.
type MPLSEchoGlobalFlags uint16

const (
	// MPLSEchoFlagValidateFECStack tweaks the FEC stack validation behavior.
	// Flag is 1 if the sender wants the receiver to perform FEC Stack validation;
	// if flag is 0, the choice is left to the receiver.
	MPLSEchoFlagValidateFECStack MPLSEchoGlobalFlags = 1 << iota // 1

	// MPLSEchoFlagRespondOnlyIfTTLExpired tweaks the "TTL expired" scenario behavior.
	// Can only be set in echo request packets.  If set to 1 in an incoming echo request and the TTL of the incoming
	// MPLS label is greater than 1, the receiving node MUST drop the oacket and MUST NOT send back an echo reply.
	MPLSEchoFlagRespondOnlyIfTTLExpired // 2

	// MPLSEchoFlagValidateReversePath acts as an opt-in for reverse-path FECs.
	// If this flag is set in the echo request, the Responder SHOULD return reverse-path FEC information (see RFC6426).
	MPLSEchoFlagValidateReversePath // 4
)

// SetMPLSEchoGlobalFlag returns an MPLSEchoGlobalFlag bitmask with the given flag enabled.
func SetMPLSEchoGlobalFlag(b, flag MPLSEchoGlobalFlags) MPLSEchoGlobalFlags { return b | flag }

// ClearMPLSEchoGlobalFlag returns an MPLSEchoGlobalFlag bitmask with the given flag disabled.
func ClearMPLSEchoGlobalFlag(b, flag MPLSEchoGlobalFlags) MPLSEchoGlobalFlags { return b &^ flag }

// HasMPLSEchoGlobalFlag returns TRUE if the given flag is enabled in the bitmask.
func HasMPLSEchoGlobalFlag(b, flag MPLSEchoGlobalFlags) bool { return b&flag != 0 }

// MPLSEchoMessageType specifies the MPLS echo message type (request/reply/...).
type MPLSEchoMessageType uint8

const (
	// MPLSEchoRequest is the "message type" value for MPLS Echo request packets.
	MPLSEchoRequest MPLSEchoMessageType = iota + 1

	// MPLSEchoReply is the "message type" value for MPLS Echo reply packets.
	MPLSEchoReply
)

// MPLSEchoReplyMode specifies the desired receiver-side behavior.
type MPLSEchoReplyMode uint8

const (
	// MPLSEchoModeDoNotReply is used for one-way connectivity tests.
	MPLSEchoModeDoNotReply MPLSEchoReplyMode = iota + 1

	// MPLSEchoModeReplyViaUDP asks for replies to use an IPv4/IPv6 UDP packet (i.e., mainstream scenario).
	MPLSEchoModeReplyViaUDP

	// MPLSEchoModeReplyViaUDPWithRouterAlert is to be used when the normal IP return path is deemed unreliable.
	// It requires that all intermediate routers know how to forward MPLS echo replies.
	MPLSEchoModeReplyViaUDPWithRouterAlert

	// MPLSEchoModeReplyViaAppLevelChannel is to be used by applications that support an IP control channel between
	// its control entities to ensure that replies use that same channel.
	MPLSEchoModeReplyViaAppLevelChannel
)

// MPLSReplyReturnCode represents an MPLS Echo operation's result, as perceived by the receiver.
// The Return Code is set to zero by the sender of an echo request. The receiver of said echo request can set it to
// one of the values listed below in the corresponding echo reply that it generates.
type MPLSReplyReturnCode uint8

// In the enum comments, <RSC> refers to the Return Subcode.
const (
	// No return code.
	MPLSEchoReturnCodeNone MPLSReplyReturnCode = iota

	// Malformed echo request received.
	MPLSEchoReturnCodeMalformedRequest

	// One or more of the TLVs was not understood.
	MPLSEchoReturnCodeTLVNotUnderstood

	// Replying router is an egress for the FEC at stack-depth <RSC>.
	MPLSEchoReturnCodeEgressForFEC

	// Replying router has no mapping for the FEC at stack-depth <RSC>.
	MPLSEchoReturnCodeNoMappingForFEC

	// Downstream Mapping Mismatch.
	MPLSEchoReturnCodeDownstreamMappingMismatch

	// Upstream Interface Index Unknown.
	MPLSEchoReturnCodeUpstreamIfaceIndexUnknown

	MPLSEchoReturnCodeReserved

	// Label switched at stack-depth <RSC>.
	MPLSEchoReturnCodeLabelSwitched

	// Label switched but no MPLS forwarding at stack-depth <RSC>.
	MPLSEchoReturnCodeLabelSwitchButNoMPLSForwarding

	// Mapping for this FEC is not the given label at stack-depth <RSC>.
	MPLSEchoReturnCodeLabelMappingMismatchForFEC

	// No label entry at stack-depth <RSC>.
	MPLSEchoReturnCodeNoLabelEntry

	// Protocol not associated with interface at FEC stack-depth <RSC>.
	MPLSEchoReturnCodeNoProtocolAtIfaceForFEC

	// Premature termination of ping due to label stack shrinking to a single label.
	MPLSEchoReturnCodePrematureTerminationSingleLabel

	// When this Return Code is set, each Downstream Detailed Mapping TLV MUST have an appropriate Return Code and
	// Return Subcode.  This Return Code MUST be used when there are multiple downstreams for a given node (such as
	// Point-to-Multipoint (P2MP) or ECMP), and the node needs to return a Return Code/Return Subcode for each
	// downstream. This Return Code MAY be used even when there is only one downstream for a given node.
	MPLSEchoReturnCodeMultipleDownstreams

	//  A transit node stitching two LSPs SHOULD include two FEC stack change sub-TLVs.  One with a pop operation for
	// the old FEC (ingress) and one with the PUSH operation for the new FEC (egress).  The replying node SHOULD set
	// the Return Code to "Label switched with FEC change" to indicate change in the FEC being traced.
	MPLSEchoReturnCodeLabelSwitchedWithFECChange
)

// MPLSEchoTLV represents a Type-Length-Value (TLV) tuple contained within an MPLS Echo request/reply packet.
// TLVs may be nested within other TLVs, in which case the nested TLVs are called sub-TLVs.
// TLVs and sub-TLVs have independent types, but both MUST be 4-octet aligned in their encoded form.
type MPLSEchoTLV struct {
	Type uint16

	// The Value field depends on the Type. When encoded, the value is zero padded to align to a 4-byte boundary.
	// The Value contents MUST be in network order (i.e., big endian).
	Value []byte
}

// List of TLV and sub-TLV types that are implemented in this file. All other types are handled as MPLSEchoTLV instances
// with arbitrary byte BLOBs as their values. Gopacket apps will need to encode/decode those (sub-)TLVs at their layer.
//
// MPLS Echo implementations may transmit non-standard (sub-)TLV types, so we use uint16 to allow for custom (sub-)TLVs.
const (
	MPLSEchoTLVTypeTargetFECStack                 uint16 = 1
	MPLSEchoSubTLVTypeTargetFECStackLDPPrefixIPv4 uint16 = 1
	MPLSEchoSubTLVTypeTargetFECStackLDPPrefixIPv6 uint16 = 2
)

// MPLSEchoValue is the interface that concrete TLV value types need to implement.
type MPLSEchoValue interface {
	// Returns value's TLV representation.
	EncodeAsTLV() (*MPLSEchoTLV, error)

	// Populates the value based on the user-provided TLV representation.
	DecodeFromTLV(tlv *MPLSEchoTLV) error
}

// LDPPrefixFECValue represents an LDP IPv4/IPv6 Prefix FEC. It implements the MPLSEchoValue interface.
type LDPPrefixFECValue struct {
	Prefix       net.IP
	PrefixLength uint8
}

// TargetFECStackValue is a TLV value type that defines a stack of FECs, the first FEC element corresponding
// to the top of the label stack, etc. It implements the MPLSEchoValue interface.
type TargetFECStackValue struct {
	FECs []MPLSEchoValue
}

// MPLSEcho is the MPLS Echo packet payload.
// An MPLS echo request/reply is a (possibly labeled) IPv4 or IPv6 UDP packet, where
// the packet's payload has the format of the MPLSEcho struct below (refer to RFC8029, Section 3).
//
// In the UDP packet's IP header:
// 1. The source IP address is a routable address of the sender.
// 2. The destination IP address is a (randomly chosen) IPv4 address from the range 127/8 or an IPv6 address
//    from the range 0:0:0:0:0:FFFF:7F00:0/104.
// 3. The IP TTL is set to 1.
// 4. The source UDP port is chosen by the sender.
// 5. The destination UDP port is set to 3503 (assigned by IANA for MPLS echo requests).
// 6. The Router Alert IP Option of value 0x0 [RFC2113] for IPv4 or value 69 [RFC7506] for IPv6 MUST be set.
type MPLSEcho struct {
	BaseLayer
	VersionNumber MPLSEchoVersion
	GlobalFlags   MPLSEchoGlobalFlags
	MessageType   MPLSEchoMessageType
	ReplyMode     MPLSEchoReplyMode
	ReturnCode    MPLSReplyReturnCode

	// The Return Subcode (RSC) contains the point in the label stack where processing was terminated.
	// If the RSC is 0, no labels were processed.  Otherwise, the packet was label switched at depth RSC.
	ReturnSubcode uint8

	// Arbitrary context filled in by the sender and returned unchanged by the receiver in the echo reply (if any).
	// There are no semantics associated with this field; a sender may use it to match up requests with replies.
	SenderHandle uint32

	// The Sequence Number is assigned by the sender of the MPLS echo request and can be (for example) used to detect
	// missed replies.
	SequenceNumber uint32

	// Time of day, according to the sender's clock, in 64-bit NTP timestamp format [RFC5905] when the MPLS echo
	// request is sent.
	TimestampSentSeconds         uint32
	TimestampSentSecondsFraction uint32 // divide by 2^32 to get the fractions of a second

	// Time of day, according to the receiver's clock, in 64-bit NTP timestamp format in which the corresponding echo
	// request was received.
	TimestampReceivedSeconds         uint32
	TimestampReceivedSecondsFraction uint32 // divide by 2^32 to get the fractions of a second

	// TLV types less than 32768 (i.e., with the high-order bit equal to 0) are mandatory TLVs that MUST either be
	// supported by an implementation or result in MPLSEchoReturnCodeTLVNotUnderstood being sent in the echo response.
	//
	// Types greater than or equal to 32768 (i.e., with the high-order bit equal to 1) are optional TLVs that SHOULD be
	// ignored if the implementation does not understand or support them.
	TLVs []*MPLSEchoTLV
}

func roundUpToNearestMultiple(numToRound uint, multiple uint) uint {
	return ((numToRound + multiple - 1) / multiple) * multiple
}

// EncodeAsBytes encodes an MPLSEchoTLV with the format below (from RFC8029, Section 3):
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             Type              |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Value                             |
// .                                                               .
// .                                                               .
// .                                                               .
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// <ZERO OR MORE ADDITIONAL TLVs> ...
func (p *MPLSEchoTLV) EncodeAsBytes() ([]byte, error) {
	valueByteCount := uint(len(p.Value))
	valueByteCountWithPadding := roundUpToNearestMultiple(valueByteCount, 4) // Pad to a multiple of 4 bytes
	tlvByteCountWithPadding := 4 + valueByteCountWithPadding
	tlvByteRepresentation := make([]byte, tlvByteCountWithPadding)
	binary.BigEndian.PutUint16(tlvByteRepresentation[0:], uint16(p.Type))
	binary.BigEndian.PutUint16(tlvByteRepresentation[2:], uint16(valueByteCount))

	bytesCopied := copy(tlvByteRepresentation[4:], p.Value[:])
	if uint(bytesCopied) != valueByteCount {
		return nil, fmt.Errorf(
			"MPLSEchoTLV encoding error - TLV of type %v, bytesCopied (%v) != valueByteCount (%v)",
			p.Type,
			bytesCopied,
			valueByteCount)
	}

	return tlvByteRepresentation, nil
}

// DecodeFromBytes decodes the provided []byte contents and populates the MPLSEchoTLV's fields with that data.
// On success, the first return value contains the total number of bytes decoded.
func (p *MPLSEchoTLV) DecodeFromBytes(data []byte) (int, error) {
	totalByteCount := len(data)
	if totalByteCount < 4 {
		return 0, fmt.Errorf(
			"MPLSEchoTLV decoding error - data is less than 4 bytes long (actual length: %v)",
			totalByteCount)
	}

	p.Type = binary.BigEndian.Uint16(data[0:2])
	valueByteCount := uint(binary.BigEndian.Uint16(data[2:4]))
	valueByteCountWithPadding := roundUpToNearestMultiple(valueByteCount, 4) // Padded to a multiple of 4 bytes

	tlvByteCountWithPadding := 4 + int(valueByteCountWithPadding)
	if tlvByteCountWithPadding > totalByteCount {
		return 0, fmt.Errorf(
			"MPLSEchoTLV decoding error - TLV of type %v goes beyond the valid data: tlvByteCountWithPadding (%v) > totalByteCount (%v)",
			p.Type,
			tlvByteCountWithPadding,
			totalByteCount)
	}

	p.Value = data[4 : 4+valueByteCount]
	return tlvByteCountWithPadding, nil
}

// EncodeAsTLV encodes an LDPPrefixFECValue in TLV format.
func (p *LDPPrefixFECValue) EncodeAsTLV() (*MPLSEchoTLV, error) {
	prefixType := MPLSEchoSubTLVTypeTargetFECStackLDPPrefixIPv4 // Assume IPv4
	prefixByteRepresentation := p.Prefix.To4()
	if prefixByteRepresentation == nil {
		prefixType = MPLSEchoSubTLVTypeTargetFECStackLDPPrefixIPv6 // Assume IPv6
		prefixByteRepresentation = p.Prefix.To16()
		if prefixByteRepresentation == nil {
			return nil, errors.New("LDPPrefixFECValue encoding error - Prefix isn't a valid IPv4 or IPv6 address")
		}
	}

	return &MPLSEchoTLV{
		Type:  prefixType,
		Value: append(prefixByteRepresentation, p.PrefixLength),
	}, nil
}

// DecodeFromTLV decodes a given TLV and populates the LDPPrefixFECValue's fields with that data.
func (p *LDPPrefixFECValue) DecodeFromTLV(tlv *MPLSEchoTLV) error {
	valueByteCount := len(tlv.Value)
	if tlv.Type == MPLSEchoSubTLVTypeTargetFECStackLDPPrefixIPv4 && valueByteCount == 5 {
		p.Prefix = tlv.Value[0:4]
		p.PrefixLength = tlv.Value[4]
	} else if tlv.Type == MPLSEchoSubTLVTypeTargetFECStackLDPPrefixIPv6 && valueByteCount == 17 {
		p.Prefix = tlv.Value[0:16]
		p.PrefixLength = tlv.Value[16]
	} else {
		return fmt.Errorf(
			"LDPPrefixFECValue decoding error - Unknown LDPPrefixFECValue type (%v) or unexpected valueByteCount (%v)",
			tlv.Type,
			valueByteCount)
	}

	return nil
}

// EncodeAsTLV encodes an TargetFECStackValue in TLV format.
func (s *TargetFECStackValue) EncodeAsTLV() (*MPLSEchoTLV, error) {
	var byteRepresentation []byte
	for _, currentFEC := range s.FECs {
		subTLV, err := currentFEC.EncodeAsTLV()
		if err != nil {
			return nil, err
		}

		subTLVBytes, err := subTLV.EncodeAsBytes()
		if err != nil {
			return nil, err
		}

		byteRepresentation = append(byteRepresentation, subTLVBytes...)
	}

	return &MPLSEchoTLV{
		Type:  MPLSEchoTLVTypeTargetFECStack,
		Value: byteRepresentation,
	}, nil
}

// DecodeFromTLV decodes a given TLV and populates the TargetFECStackValue's fields with that data.
func (s *TargetFECStackValue) DecodeFromTLV(tlv *MPLSEchoTLV) error {
	if tlv.Type != MPLSEchoTLVTypeTargetFECStack {
		return fmt.Errorf(
			"TargetFECStackValue decoding error - type mismatch: expected %v, got %v",
			MPLSEchoTLVTypeTargetFECStack,
			tlv.Type)
	}

	s.FECs = nil
	currentTLVStartOffset := 0
	valueByteCount := len(tlv.Value)
	for currentTLVStartOffset < valueByteCount {
		currentTLV := &MPLSEchoTLV{}
		numBytesDecoded, err := currentTLV.DecodeFromBytes(tlv.Value[currentTLVStartOffset:])
		if err != nil {
			return err
		}

		var newFEC MPLSEchoValue
		switch currentTLV.Type {
		case MPLSEchoSubTLVTypeTargetFECStackLDPPrefixIPv4:
			fallthrough
		case MPLSEchoSubTLVTypeTargetFECStackLDPPrefixIPv6:
			newFEC = &LDPPrefixFECValue{}
			err = newFEC.DecodeFromTLV(currentTLV)
			if err != nil {
				return err
			}

		default:
			return fmt.Errorf("TargetFECStackValue decoding error - unknown sub-type: %v", currentTLV.Type)
		}

		s.FECs = append(s.FECs, newFEC)
		currentTLVStartOffset += numBytesDecoded
	}

	if currentTLVStartOffset != valueByteCount {
		return fmt.Errorf(
			"TargetFECStackValue decoding error - sub-TLVs don't match the valid data bounds (Total Valid Bytes = %v, Last TLV End Offset = %v)",
			valueByteCount,
			currentTLVStartOffset)
	}

	return nil
}

// LayerType returns gopacket.LayerTypeMPLSEcho.
func (m *MPLSEcho) LayerType() gopacket.LayerType {
	return LayerTypeMPLSEcho
}

// DecodeFromBytes decodes the given bytes into this layer.
func (m *MPLSEcho) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 32 {
		df.SetTruncated()
		return fmt.Errorf("Invalid MPLSEcho content - length %v less than 32 bytes", len(data))
	}

	totalTLVBytes := len(data) - 32
	if totalTLVBytes%4 != 0 {
		return fmt.Errorf("Invalid MPLSEcho content - TLVs aren't 4-octet aligned (TLV bytes = %v)", totalTLVBytes)
	}

	m.VersionNumber = MPLSEchoVersion(binary.BigEndian.Uint16(data[0:2]))
	m.GlobalFlags = MPLSEchoGlobalFlags(binary.BigEndian.Uint16(data[2:4]))
	m.MessageType = MPLSEchoMessageType(data[4])
	m.ReplyMode = MPLSEchoReplyMode(data[5])
	m.ReturnCode = MPLSReplyReturnCode(data[6])
	m.ReturnSubcode = data[7]
	m.SenderHandle = binary.BigEndian.Uint32(data[8:12])
	m.SequenceNumber = binary.BigEndian.Uint32(data[12:16])
	m.TimestampSentSeconds = binary.BigEndian.Uint32(data[16:20])
	m.TimestampSentSecondsFraction = binary.BigEndian.Uint32(data[20:24])
	m.TimestampReceivedSeconds = binary.BigEndian.Uint32(data[24:28])
	m.TimestampReceivedSecondsFraction = binary.BigEndian.Uint32(data[28:32])

	currentTLVStartOffset := 32
	for currentTLVStartOffset < len(data) {
		currentTLV := &MPLSEchoTLV{}
		numBytesDecoded, err := currentTLV.DecodeFromBytes(data[currentTLVStartOffset:])
		if err != nil {
			return err
		}

		m.TLVs = append(m.TLVs, currentTLV)
		currentTLVStartOffset += numBytesDecoded
	}

	if currentTLVStartOffset != len(data) {
		return fmt.Errorf(
			"Invalid MPLSEcho content - TLVs don't match the valid data bounds (Total Valid Bytes = %v, Last TLV End Offset = %v)",
			len(data),
			currentTLVStartOffset)
	}

	return nil

}

// SerializeTo writes the serialized form of this layer into the SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (m *MPLSEcho) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	totalBytes := 32
	for _, currentTLV := range m.TLVs {
		valueByteCount := uint(len(currentTLV.Value))
		tlvByteCountWithPadding := 4 + roundUpToNearestMultiple(valueByteCount, 4) // Pad to a multiple of 4 bytes
		totalBytes += int(tlvByteCountWithPadding)
	}

	bytes, err := b.PrependBytes(totalBytes)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(m.VersionNumber))
	binary.BigEndian.PutUint16(bytes[2:], uint16(m.GlobalFlags))
	bytes[4] = uint8(m.MessageType)
	bytes[5] = uint8(m.ReplyMode)
	bytes[6] = uint8(m.ReturnCode)
	bytes[7] = uint8(m.ReturnSubcode)
	binary.BigEndian.PutUint32(bytes[8:], m.SenderHandle)
	binary.BigEndian.PutUint32(bytes[12:], m.SequenceNumber)
	binary.BigEndian.PutUint32(bytes[16:], m.TimestampSentSeconds)
	binary.BigEndian.PutUint32(bytes[20:], m.TimestampSentSecondsFraction)
	binary.BigEndian.PutUint32(bytes[24:], m.TimestampReceivedSeconds)
	binary.BigEndian.PutUint32(bytes[28:], m.TimestampReceivedSecondsFraction)

	currentTLVStartOffset := 32
	for _, currentTLV := range m.TLVs {
		tlvByteRepresentation, err := currentTLV.EncodeAsBytes()
		if err != nil {
			return err
		}

		tlvByteCount := len(tlvByteRepresentation)
		totalBytesNeeded := currentTLVStartOffset + tlvByteCount
		if totalBytesNeeded > totalBytes {
			return fmt.Errorf(
				"MPLSEcho serialization error for TLV of type %v: totalBytesNeeded (%v) > totalBytes (%v)",
				currentTLV.Type,
				totalBytesNeeded,
				totalBytes)
		}

		bytesCopied := copy(bytes[currentTLVStartOffset:], tlvByteRepresentation[:])
		if bytesCopied != tlvByteCount {
			return fmt.Errorf(
				"MPLSEcho serialization error for TLV of type %v: bytesCopied (%v) != tlvByteCount (%v)",
				currentTLV.Type,
				bytesCopied,
				tlvByteCount)
		}

		currentTLVStartOffset = totalBytesNeeded
	}

	if currentTLVStartOffset != totalBytes {
		return fmt.Errorf(
			"Unexpected MPLSEcho serialization error: Last TLV End Offset (%v) != totalBytes (%v)",
			currentTLVStartOffset,
			totalBytes)
	}

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (m *MPLSEcho) CanDecode() gopacket.LayerClass {
	return LayerTypeMPLSEcho
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (m *MPLSEcho) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func decodeMPLSEcho(data []byte, p gopacket.PacketBuilder) error {
	d := &MPLSEcho{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(d)
	return nil
}
