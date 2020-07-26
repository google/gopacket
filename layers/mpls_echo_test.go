// Copyright 2018 GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"github.com/google/gopacket"
	"net"
	"reflect"
	"runtime"
	"testing"
)

// Based on Wireshark capture of LSP Ping operation on CISCO IOS-XRv 9000 device.
// CISCO CLI command: ping mpls ipv4 104.44.1.118/32
func TestMPLSEcho_FullEncodedPacket_MatchesWiresharkDump(t *testing.T) {
	// MPLS Echo Request
	//
	// Frame 9: 110 bytes on wire (880 bits), 110 bytes captured (880 bits)
	// Ethernet II, Src: 52:54:f3:02:fd:7a (52:54:f3:02:fd:7a), Dst: Cisco_45:7f:2b (00:30:7b:45:7f:2b)
	// 	Destination: Cisco_45:7f:2b (00:30:7b:45:7f:2b)
	// 	Source: 52:54:f3:02:fd:7a (52:54:f3:02:fd:7a)
	// 	Type: IPv4 (0x0800)
	// Internet Protocol Version 4, Src: 104.44.18.245, Dst: 127.0.0.1
	// User Datagram Protocol, Src Port: 3503, Dst Port: 3503
	// 	Source Port: 3503
	// 	Destination Port: 3503
	// 	Length: 72
	// 	Checksum: 0x18a1 [unverified]
	// 	[Checksum Status: Unverified]
	// 	[Stream index: 0]
	// 	[Timestamps]
	// Multiprotocol Label Switching Echo
	// 	Version: 1
	// 	Global Flags: 0x0000
	// 	Message Type: MPLS Echo Request (1)
	// 	Reply Mode: Reply via an IPv4/IPv6 UDP packet (2)
	// 	Return Code: No return code (0)
	// 	Return Subcode: 0
	// 	Sender's Handle: 0x289514a2
	// 	Sequence Number: 1
	// 	Timestamp Sent: Jul  2, 2019 21:50:30.489873816 UTC
	// 	Timestamp Received: Feb  7, 2036 06:28:16.000000000 UTC
	// 	Vendor Private
	// 		Type: Vendor Private (64512)
	// 		Length: 12
	// 		Vendor Id: ciscoSystems (9)
	// 		Value: 0001000400000004
	// 	Target FEC Stack
	// 		Type: Target FEC Stack (1)
	// 		Length: 12
	// 		FEC Element 1: LDP IPv4 prefix
	// 			Type: LDP IPv4 prefix (1)
	// 			Length: 5
	// 			IPv4 Prefix: 104.44.1.118
	// 			Prefix Length: 32
	// 			Padding: 000000
	expectedRequestPacketBytes := []byte{
		0x00, 0x30, 0x7b, 0x45, 0x7f, 0x2b, 0x52, 0x54, 0xf3, 0x02, 0xfd, 0x7a, 0x08, 0x00, 0x46, 0x00,
		0x00, 0x60, 0x01, 0x31, 0x40, 0x00, 0x01, 0x11, 0xe9, 0x35, 0x68, 0x2c, 0x12, 0xf5, 0x7f, 0x00,
		0x00, 0x01, 0x94, 0x04, 0x00, 0x00, 0x0d, 0xaf, 0x0d, 0xaf, 0x00, 0x48, 0x18, 0xa1, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x28, 0x95, 0x14, 0xa2, 0x00, 0x00, 0x00, 0x01, 0xe0, 0xc6,
		0x50, 0x26, 0x7d, 0x68, 0x5e, 0xd7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x00,
		0x00, 0x0c, 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01,
		0x00, 0x0c, 0x00, 0x01, 0x00, 0x05, 0x68, 0x2c, 0x01, 0x76, 0x20, 0x00, 0x00, 0x00,
	}

	// MPLS Echo Reply
	//
	// Frame 7: 90 bytes on wire (720 bits), 90 bytes captured (720 bits)
	// Ethernet II, Src: 52:54:91:a8:48:40 (52:54:91:a8:48:40), Dst: Cisco_21:8d:f2 (00:10:7b:21:8d:f2)
	// 	Destination: Cisco_21:8d:f2 (00:10:7b:21:8d:f2)
	// 	Source: 52:54:91:a8:48:40 (52:54:91:a8:48:40)
	// 	Type: IPv4 (0x0800)
	// Internet Protocol Version 4, Src: 104.44.18.244, Dst: 104.44.18.245
	// User Datagram Protocol, Src Port: 3503, Dst Port: 3503
	// 	Source Port: 3503
	// 	Destination Port: 3503
	// 	Length: 56
	// 	Checksum: 0xd42b [unverified]
	// 	[Checksum Status: Unverified]
	// 	[Stream index: 0]
	// 	[Timestamps]
	// Multiprotocol Label Switching Echo
	// 	Version: 1
	// 	Global Flags: 0x0000
	// 	Message Type: MPLS Echo Reply (2)
	// 	Reply Mode: Reply via an IPv4/IPv6 UDP packet (2)
	// 	Return Code: Replying router is an egress for the FEC at stack depth RSC (3)
	// 	Return Subcode: 1
	// 	Sender's Handle: 0x289514a2
	// 	Sequence Number: 1
	// 	Timestamp Sent: Jul  2, 2019 21:50:30.489873816 UTC
	// 	Timestamp Received: Jul  2, 2019 21:50:31.489873817 UTC
	// 	Vendor Private
	echoReplyPacketBytes := []byte{
		0x00, 0x10, 0x7b, 0x21, 0x8d, 0xf2, 0x52, 0x54, 0x91, 0xa8, 0x48, 0x40, 0x08, 0x00, 0x45, 0xc0,
		0x00, 0x4c, 0x01, 0x45, 0x00, 0x00, 0xff, 0x11, 0xc3, 0x5a, 0x68, 0x2c, 0x12, 0xf4, 0x68, 0x2c,
		0x12, 0xf5, 0x0d, 0xaf, 0x0d, 0xaf, 0x00, 0x38, 0xd4, 0x2b, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02,
		0x03, 0x01, 0x28, 0x95, 0x14, 0xa2, 0x00, 0x00, 0x00, 0x01, 0xe0, 0xc6, 0x50, 0x26, 0x7d, 0x68,
		0x5e, 0xd7, 0xe0, 0xc6, 0x50, 0x27, 0x7d, 0x68, 0x5e, 0xd8, 0xfc, 0x00, 0x00, 0x0c, 0x00, 0x00,
		0x00, 0x09, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
	}

	ethernet := &Ethernet{
		SrcMAC:       net.HardwareAddr{0x52, 0x54, 0xf3, 0x02, 0xfd, 0x7a},
		DstMAC:       net.HardwareAddr{0x00, 0x30, 0x7b, 0x45, 0x7f, 0x2b},
		EthernetType: EthernetTypeIPv4,
	}

	ip := &IPv4{
		Version:  4,
		IHL:      24,
		Length:   96,
		Id:       0x0131,
		Flags:    IPv4DontFragment,
		TTL:      1,
		Protocol: IPProtocolUDP,
		SrcIP:    net.IP{104, 44, 18, 245},
		DstIP:    net.IP{127, 0, 0, 1},
		Options:  []IPv4Option{IPv4Option{OptionType: 148, OptionLength: 4, OptionData: []byte{0x0, 0x0}}},
	}

	udp := &UDP{
		SrcPort: 3503,
		DstPort: 3503,
		Length:  72,
	}
	err := udp.SetNetworkLayerForChecksum(ip)
	verifyNil(t, err)

	// Build the Target FEC Stack TLV.
	targetPrefixIP := net.ParseIP("104.44.1.118")
	verifyNotNil(t, targetPrefixIP)

	targetFECStackVal := TargetFECStackValue{
		FECs: []MPLSEchoValue{
			&LDPPrefixFECValue{
				Prefix:       targetPrefixIP,
				PrefixLength: 32,
			},
		},
	}

	targetFECStackAsTLV, err := targetFECStackVal.EncodeAsTLV()
	verifyNil(t, err)
	verifyNotNil(t, targetFECStackAsTLV)

	mplsEchoRequestContents := &MPLSEcho{
		VersionNumber:                    MPLSEchoVersion1,
		GlobalFlags:                      0,
		MessageType:                      MPLSEchoRequest,
		ReplyMode:                        MPLSEchoModeReplyViaUDP,
		ReturnCode:                       MPLSEchoReturnCodeNone,
		ReturnSubcode:                    0,
		SenderHandle:                     0x289514a2,
		SequenceNumber:                   1,
		TimestampSentSeconds:             0xe0c65026,
		TimestampSentSecondsFraction:     0x7d685ed7,
		TimestampReceivedSeconds:         0,
		TimestampReceivedSecondsFraction: 0,
		TLVs: []*MPLSEchoTLV{
			// Vendor Private TLV.
			&MPLSEchoTLV{Type: 64512, Value: []byte{0x0, 0x0, 0x0, 0x9, 0x0, 0x1, 0x0, 0x4, 0x0, 0x0, 0x0, 0x4}},

			// Target FEC Stack TLV.
			targetFECStackAsTLV,
		},
	}

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		buffer,
		options,
		ethernet,
		ip,
		udp,
		mplsEchoRequestContents)
	verifyNil(t, err)

	// The encoded MPLS Echo request should match the Wireshark capture's raw bytes.
	requestPacketBytes := buffer.Bytes()
	verifyEqual(t, expectedRequestPacketBytes, requestPacketBytes)

	// The decoded MPLS Echo reply should match the Wireshark capture's contents.
	replyPacket := gopacket.NewPacket(echoReplyPacketBytes, LayerTypeEthernet, gopacket.Lazy)
	mplsEchoReplyLayer := replyPacket.Layer(LayerTypeMPLSEcho)
	verifyNotNil(t, mplsEchoReplyLayer)

	mplsEchoReplyContents, ok := mplsEchoReplyLayer.(*MPLSEcho)
	verifyTrue(t, ok)

	// Fields that should match the MPLS Echo request.
	verifyEqual(t, mplsEchoRequestContents.VersionNumber, mplsEchoReplyContents.VersionNumber)
	verifyEqual(t, mplsEchoRequestContents.GlobalFlags, mplsEchoReplyContents.GlobalFlags)
	verifyEqual(t, mplsEchoRequestContents.SenderHandle, mplsEchoReplyContents.SenderHandle)
	verifyEqual(t, mplsEchoRequestContents.SequenceNumber, mplsEchoReplyContents.SequenceNumber)
	verifyEqual(t, mplsEchoRequestContents.TimestampSentSeconds, mplsEchoReplyContents.TimestampSentSeconds)
	verifyEqual(t, mplsEchoRequestContents.TimestampSentSecondsFraction, mplsEchoReplyContents.TimestampSentSecondsFraction)

	// Fields generated by the MPLS Echo request's receiver.
	verifyEqual(t, MPLSEchoReply, mplsEchoReplyContents.MessageType)
	verifyEqual(t, MPLSEchoReturnCodeEgressForFEC, mplsEchoReplyContents.ReturnCode)
	verifyEqual(t, uint8(1), mplsEchoReplyContents.ReturnSubcode)
	verifyEqual(t, uint32(0xe0c65027), mplsEchoReplyContents.TimestampReceivedSeconds)
	verifyEqual(t, uint32(0x7d685ed8), mplsEchoReplyContents.TimestampReceivedSecondsFraction)

	// Reply should contain the vendor-private TLV, but not the Target FEC Stack TLV.
	verifyEqual(t, 1, len(mplsEchoReplyContents.TLVs))
	verifyEqual(t, mplsEchoRequestContents.TLVs[0].Type, mplsEchoReplyContents.TLVs[0].Type)
	verifyEqual(t, mplsEchoRequestContents.TLVs[0].Value, mplsEchoReplyContents.TLVs[0].Value)

	// Try to decode 'targetFECStackAsTLV' the same way that a receiver would.
	verifyEqual(t, MPLSEchoTLVTypeTargetFECStack, mplsEchoRequestContents.TLVs[1].Type)
	targetFECStack := &TargetFECStackValue{}
	err = targetFECStack.DecodeFromTLV(mplsEchoRequestContents.TLVs[1])
	verifyNil(t, err)

	verifyEqual(t, 1, len(targetFECStack.FECs))
	ldpPrefixFECValue, ok := targetFECStack.FECs[0].(*LDPPrefixFECValue)
	verifyTrue(t, ok)

	verifyEqual(t, uint8(32), ldpPrefixFECValue.PrefixLength)
	verifyEqual(t, targetPrefixIP.To4(), ldpPrefixFECValue.Prefix)
}

func TestMPLSEcho_DecodeUnexpectedlyShortByteArray_Fail(t *testing.T) {
	// Byte array containing less than 32 bytes.
	badData := []byte{0x1, 0x2, 0x3}

	decodedMPLSEcho := &MPLSEcho{}
	err := decodedMPLSEcho.DecodeFromBytes(badData, gopacket.NilDecodeFeedback)
	verifyNotNil(t, err)
	verifyEqual(t,
		"Invalid MPLSEcho content - length 3 less than 32 bytes",
		err.Error())
}

func TestMPLSEcho_DecodeUnalignedTLVs_Fail(t *testing.T) {
	validMplsEchoRequestContents := &MPLSEcho{
		VersionNumber:                    MPLSEchoVersion1,
		GlobalFlags:                      0,
		MessageType:                      MPLSEchoRequest,
		ReplyMode:                        MPLSEchoModeReplyViaUDP,
		ReturnCode:                       MPLSEchoReturnCodeNone,
		ReturnSubcode:                    0,
		SenderHandle:                     0x289514a2,
		SequenceNumber:                   1,
		TimestampSentSeconds:             0xe0c65026,
		TimestampSentSecondsFraction:     0x7d685ed7,
		TimestampReceivedSeconds:         0,
		TimestampReceivedSecondsFraction: 0,
		TLVs: []*MPLSEchoTLV{
			// Vendor Private TLV.
			&MPLSEchoTLV{Type: 64512, Value: []byte{0x0, 0x0, 0x0, 0x9, 0x0, 0x1, 0x0, 0x4, 0x0, 0x0, 0x0, 0x4}},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := validMplsEchoRequestContents.SerializeTo(buf, opts)
	verifyNil(t, err)

	// Append an extra byte to the end of the TLV section, so it's no longer 4-octet aligned.
	validEncodedBytes := buf.Bytes()
	badEncodedBytes := append(validEncodedBytes, 0x1)

	decodedMPLSEcho := &MPLSEcho{}
	err = decodedMPLSEcho.DecodeFromBytes(badEncodedBytes, gopacket.NilDecodeFeedback)
	verifyNotNil(t, err)
	verifyEqual(t,
		"Invalid MPLSEcho content - TLVs aren't 4-octet aligned (TLV bytes = 17)",
		err.Error())
}

func TestMPLSEcho_DecodeMaliciousTLVs_Fail(t *testing.T) {
	validMplsEchoRequestContents := &MPLSEcho{
		VersionNumber:                    MPLSEchoVersion1,
		GlobalFlags:                      0,
		MessageType:                      MPLSEchoRequest,
		ReplyMode:                        MPLSEchoModeReplyViaUDP,
		ReturnCode:                       MPLSEchoReturnCodeNone,
		ReturnSubcode:                    0,
		SenderHandle:                     0x289514a2,
		SequenceNumber:                   1,
		TimestampSentSeconds:             0xe0c65026,
		TimestampSentSecondsFraction:     0x7d685ed7,
		TimestampReceivedSeconds:         0,
		TimestampReceivedSecondsFraction: 0,
		TLVs: []*MPLSEchoTLV{
			// Vendor Private TLV.
			&MPLSEchoTLV{Type: 64512, Value: []byte{0x0, 0x0, 0x0, 0x9, 0x0, 0x1, 0x0, 0x4, 0x0, 0x0, 0x0, 0x4}},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := validMplsEchoRequestContents.SerializeTo(buf, opts)
	verifyNil(t, err)

	// Craft a TLV encoding that attempts to force a read outside of valid data boundaries.
	badEncodedBytes := buf.Bytes()
	badEncodedBytes[34] = 0xFF
	badEncodedBytes[35] = 0xFF

	decodedMPLSEcho := &MPLSEcho{}
	err = decodedMPLSEcho.DecodeFromBytes(badEncodedBytes, gopacket.NilDecodeFeedback)
	verifyNotNil(t, err)
	verifyEqual(t,
		"MPLSEchoTLV decoding error - TLV of type 64512 goes beyond the valid data: tlvByteCountWithPadding (65540) > totalByteCount (16)",
		err.Error())
}

func TestMPLSEcho_CanDecode_ReturnsExpectedValue(t *testing.T) {
	mplsEcho := &MPLSEcho{}
	verifyEqual(t, LayerTypeMPLSEcho, mplsEcho.CanDecode())
}

func TestMPLSEcho_NextLayerType_ReturnsExpectedValue(t *testing.T) {
	mplsEcho := &MPLSEcho{}
	verifyEqual(t, gopacket.LayerTypeZero, mplsEcho.NextLayerType())
}

func TestMPLSEchoGlobalFlags_SetClearHas_ExpectedBehavior(t *testing.T) {
	globalFlags := MPLSEchoGlobalFlags(0)
	verifyFalse(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateFECStack))
	verifyFalse(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagRespondOnlyIfTTLExpired))
	verifyFalse(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateReversePath))

	globalFlags = SetMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagRespondOnlyIfTTLExpired)
	verifyFalse(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateFECStack))
	verifyTrue(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagRespondOnlyIfTTLExpired))
	verifyFalse(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateReversePath))

	globalFlags = SetMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateFECStack)
	verifyTrue(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateFECStack))
	verifyTrue(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagRespondOnlyIfTTLExpired))
	verifyFalse(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateReversePath))

	globalFlags = SetMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateReversePath)
	verifyTrue(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateFECStack))
	verifyTrue(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagRespondOnlyIfTTLExpired))
	verifyTrue(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateReversePath))

	globalFlags = ClearMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagRespondOnlyIfTTLExpired)
	verifyTrue(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateFECStack))
	verifyFalse(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagRespondOnlyIfTTLExpired))
	verifyTrue(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateReversePath))

	globalFlags = ClearMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateReversePath)
	verifyTrue(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateFECStack))
	verifyFalse(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagRespondOnlyIfTTLExpired))
	verifyFalse(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateReversePath))

	globalFlags = ClearMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateFECStack)
	verifyFalse(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateFECStack))
	verifyFalse(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagRespondOnlyIfTTLExpired))
	verifyFalse(t, HasMPLSEchoGlobalFlag(globalFlags, MPLSEchoFlagValidateReversePath))
}

func TestMPLSEchoTLV_EncodeDecodeEmptyValue_Success(t *testing.T) {
	emptyValueTLV := &MPLSEchoTLV{
		Type:  1337,
		Value: nil,
	}

	encodedBytes, err := emptyValueTLV.EncodeAsBytes()
	verifyNil(t, err)
	verifyNotNil(t, encodedBytes)
	verifyEqual(t, 4, len(encodedBytes))

	decodedTLV := &MPLSEchoTLV{}
	numBytesDecoded, err := decodedTLV.DecodeFromBytes(encodedBytes)
	verifyNil(t, err)
	verifyEqual(t, 4, numBytesDecoded)

	verifyEqual(t, emptyValueTLV.Type, decodedTLV.Type)
	verifyNotNil(t, decodedTLV.Value)
	verifyEqual(t, 0, len(decodedTLV.Value))
}

func TestMPLSEchoTLV_EncodeDecodeUnalignedValue_Success(t *testing.T) {
	// Value that isn't 4-octet aligned.
	unalignedValueTLV := &MPLSEchoTLV{
		Type:  101,
		Value: []byte{0xB, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF}, // 7-byte value
	}

	encodedBytes, err := unalignedValueTLV.EncodeAsBytes()
	verifyNil(t, err)
	verifyNotNil(t, encodedBytes)
	verifyEqual(t, 12, len(encodedBytes)) // 4 + 7-byte value + 1-byte padding

	decodedTLV := &MPLSEchoTLV{}
	numBytesDecoded, err := decodedTLV.DecodeFromBytes(encodedBytes)
	verifyNil(t, err)
	verifyEqual(t, 12, numBytesDecoded)

	verifyEqual(t, unalignedValueTLV.Type, decodedTLV.Type)
	verifyNotNil(t, decodedTLV.Value)
	verifyEqual(t, unalignedValueTLV.Value, decodedTLV.Value)
}

func TestMPLSEchoTLV_EncodeDecodeAlignedValue_Success(t *testing.T) {
	// Value that is 4-octet aligned.
	unalignedValueTLV := &MPLSEchoTLV{
		Type:  65535,
		Value: []byte{0xB, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF, 0xF}, // 8-byte value
	}

	encodedBytes, err := unalignedValueTLV.EncodeAsBytes()
	verifyNil(t, err)
	verifyNotNil(t, encodedBytes)
	verifyEqual(t, 12, len(encodedBytes)) // 4 + 8-byte value

	decodedTLV := &MPLSEchoTLV{}
	numBytesDecoded, err := decodedTLV.DecodeFromBytes(encodedBytes)
	verifyNil(t, err)
	verifyEqual(t, 12, numBytesDecoded)

	verifyEqual(t, unalignedValueTLV.Type, decodedTLV.Type)
	verifyNotNil(t, decodedTLV.Value)
	verifyEqual(t, unalignedValueTLV.Value, decodedTLV.Value)
}

// Decode a byte array containing multiple TLVs.
func TestMPLSEchoTLV_DecodeConcatenatedTLVs_Success(t *testing.T) {
	originalTLVs := []*MPLSEchoTLV{
		&MPLSEchoTLV{
			Type:  65535,
			Value: []byte{0xB, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF},
		},
		&MPLSEchoTLV{
			Type:  65534,
			Value: []byte{0xA, 0xB, 0xC, 0xD, 0xE, 0xF},
		},
		&MPLSEchoTLV{
			Type:  7,
			Value: []byte{0x1, 0x3, 0x3, 0x7},
		},
	}

	var allTLVBytes []byte
	for _, currentTLV := range originalTLVs {
		encodedBytes, err := currentTLV.EncodeAsBytes()
		verifyNil(t, err)

		allTLVBytes = append(allTLVBytes, encodedBytes...)
	}

	// Decode all bytes by calling DecodeFromBytes multiple times.
	currentOffset := 0
	var decodedTLVs []*MPLSEchoTLV
	for currentOffset < len(allTLVBytes) {
		currentTLV := &MPLSEchoTLV{}
		numBytesDecoded, err := currentTLV.DecodeFromBytes(allTLVBytes[currentOffset:])
		verifyNil(t, err)
		verifyLessOrEqual(t, numBytesDecoded, len(allTLVBytes)-currentOffset)

		decodedTLVs = append(decodedTLVs, currentTLV)
		currentOffset += numBytesDecoded
	}

	verifyEqual(t, len(allTLVBytes), currentOffset)
	verifyEqual(t, originalTLVs, decodedTLVs)
}

func TestMPLSEchoTLV_DecodeUnexpectedlyShortByteArray_Fail(t *testing.T) {
	// Byte array containing less than 4 bytes.
	badData := []byte{0x1, 0x2, 0x3}

	decodedTLV := &MPLSEchoTLV{}
	numBytesDecoded, err := decodedTLV.DecodeFromBytes(badData)
	verifyEqual(t, 0, numBytesDecoded)
	verifyNotNil(t, err)
	verifyEqual(t,
		"MPLSEchoTLV decoding error - data is less than 4 bytes long (actual length: 3)",
		err.Error())
}

func TestMPLSEchoTLV_DecodeMaliciousData_Fail(t *testing.T) {
	// Encoding that attempts to force a read outside of valid data boundaries.
	maliciousData := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x3, 0x5}

	decodedTLV := &MPLSEchoTLV{}
	numBytesDecoded, err := decodedTLV.DecodeFromBytes(maliciousData)
	verifyEqual(t, 0, numBytesDecoded)
	verifyNotNil(t, err)
	verifyEqual(t,
		"MPLSEchoTLV decoding error - TLV of type 65535 goes beyond the valid data: tlvByteCountWithPadding (65540) > totalByteCount (6)",
		err.Error())
}

func TestLDPPrefixFECValue_EncodeDecodeIPv4_Success(t *testing.T) {
	targetPrefixIP := net.ParseIP("1.2.3.0")
	verifyNotNil(t, targetPrefixIP)

	originalFEC := &LDPPrefixFECValue{
		Prefix:       targetPrefixIP,
		PrefixLength: 24,
	}

	encodedFEC, err := originalFEC.EncodeAsTLV()
	verifyNil(t, err)
	verifyNotNil(t, encodedFEC)
	verifyEqual(t, MPLSEchoSubTLVTypeTargetFECStackLDPPrefixIPv4, encodedFEC.Type)

	decodedFEC := &LDPPrefixFECValue{}
	err = decodedFEC.DecodeFromTLV(encodedFEC)
	verifyNil(t, err)

	verifyEqual(t, originalFEC.PrefixLength, decodedFEC.PrefixLength)
	verifyEqual(t, originalFEC.Prefix.To4(), decodedFEC.Prefix)
}

func TestLDPPrefixFECValue_EncodeDecodeIPv6_Success(t *testing.T) {
	targetPrefixIP := net.ParseIP("2001:db8:abcd:0012::0")
	verifyNotNil(t, targetPrefixIP)

	originalFEC := &LDPPrefixFECValue{
		Prefix:       targetPrefixIP,
		PrefixLength: 64,
	}

	encodedFEC, err := originalFEC.EncodeAsTLV()
	verifyNil(t, err)
	verifyNotNil(t, encodedFEC)
	verifyEqual(t, MPLSEchoSubTLVTypeTargetFECStackLDPPrefixIPv6, encodedFEC.Type)

	decodedFEC := &LDPPrefixFECValue{}
	err = decodedFEC.DecodeFromTLV(encodedFEC)
	verifyNil(t, err)

	verifyEqual(t, originalFEC.PrefixLength, decodedFEC.PrefixLength)
	verifyEqual(t, originalFEC.Prefix.To16(), decodedFEC.Prefix)
}

func TestLDPPrefixFECValue_EncodeInvalidPrefixIP_Fail(t *testing.T) {
	invalidPrefixIP := net.IP{0x1, 0x0, 0x1} // Not a a valid IPv4 or IPv6 address
	originalFEC := &LDPPrefixFECValue{
		Prefix:       invalidPrefixIP,
		PrefixLength: 1,
	}

	encodedFEC, err := originalFEC.EncodeAsTLV()
	verifyNil(t, encodedFEC)
	verifyNotNil(t, err)
	verifyEqual(t,
		"LDPPrefixFECValue encoding error - Prefix isn't a valid IPv4 or IPv6 address",
		err.Error())
}

func TestLDPPrefixFECValue_DecodeUnknownType_Fail(t *testing.T) {
	unknownTypeTLV := &MPLSEchoTLV{
		Type:  1337,                             // Unknown type
		Value: []byte{0x1, 0x2, 0x3, 0x0, 0x18}, // Valid IPv4 address + prefix length
	}

	decodedFEC := &LDPPrefixFECValue{}
	err := decodedFEC.DecodeFromTLV(unknownTypeTLV)
	verifyNotNil(t, err)
	verifyEqual(t,
		"LDPPrefixFECValue decoding error - Unknown LDPPrefixFECValue type (1337) or unexpected valueByteCount (5)",
		err.Error())
}

func TestLDPPrefixFECValue_DecodeUnexpectedByteCount_Fail(t *testing.T) {
	unknownTypeTLV := &MPLSEchoTLV{
		Type:  MPLSEchoSubTLVTypeTargetFECStackLDPPrefixIPv4,
		Value: []byte{0x1, 0x2, 0x3, 0x0, 0x1, 0x18}, // Too long for an IPv4 address + prefix length
	}

	decodedFEC := &LDPPrefixFECValue{}
	err := decodedFEC.DecodeFromTLV(unknownTypeTLV)
	verifyNotNil(t, err)
	verifyEqual(t,
		"LDPPrefixFECValue decoding error - Unknown LDPPrefixFECValue type (1) or unexpected valueByteCount (6)",
		err.Error())
}

func TestTargetFECStackValue_EncodeDecodeSingleIPv4FEC_Success(t *testing.T) {
	targetPrefixIPv4 := net.ParseIP("104.44.1.0")
	verifyNotNil(t, targetPrefixIPv4)

	originalFECStackIPv4Val := TargetFECStackValue{
		FECs: []MPLSEchoValue{
			&LDPPrefixFECValue{
				Prefix:       targetPrefixIPv4.To4(),
				PrefixLength: 24,
			},
		},
	}

	encodedFECStackVal, err := originalFECStackIPv4Val.EncodeAsTLV()
	verifyNil(t, err)
	verifyNotNil(t, encodedFECStackVal)
	verifyEqual(t, MPLSEchoTLVTypeTargetFECStack, encodedFECStackVal.Type)

	decodedFECStackVal := &TargetFECStackValue{}
	err = decodedFECStackVal.DecodeFromTLV(encodedFECStackVal)
	verifyNil(t, err)

	verifyEqual(t, originalFECStackIPv4Val.FECs, decodedFECStackVal.FECs)
}

func TestTargetFECStackValue_EncodeDecodeSingleIPv6FEC_Success(t *testing.T) {
	targetPrefixIPv6 := net.ParseIP("2001:db8:abcd:0012::0")
	verifyNotNil(t, targetPrefixIPv6)

	originalFECStackIPv6Val := TargetFECStackValue{
		FECs: []MPLSEchoValue{
			&LDPPrefixFECValue{
				Prefix:       targetPrefixIPv6.To16(),
				PrefixLength: 64,
			},
		},
	}

	encodedFECStackVal, err := originalFECStackIPv6Val.EncodeAsTLV()
	verifyNil(t, err)
	verifyNotNil(t, encodedFECStackVal)
	verifyEqual(t, MPLSEchoTLVTypeTargetFECStack, encodedFECStackVal.Type)

	decodedFECStackVal := &TargetFECStackValue{}
	err = decodedFECStackVal.DecodeFromTLV(encodedFECStackVal)
	verifyNil(t, err)

	verifyEqual(t, originalFECStackIPv6Val.FECs, decodedFECStackVal.FECs)
}

func TestTargetFECStackValue_EncodeDecodeMultipleFECs_Success(t *testing.T) {
	targetPrefixIPv4 := net.ParseIP("104.44.1.0")
	verifyNotNil(t, targetPrefixIPv4)

	targetPrefixIPv6 := net.ParseIP("2001:db8:abcd:0012::0")
	verifyNotNil(t, targetPrefixIPv6)

	originalFECStackVal := TargetFECStackValue{
		FECs: []MPLSEchoValue{
			&LDPPrefixFECValue{
				Prefix:       targetPrefixIPv6.To16(),
				PrefixLength: 64,
			},
			&LDPPrefixFECValue{
				Prefix:       targetPrefixIPv6.To16(),
				PrefixLength: 64,
			},
			&LDPPrefixFECValue{
				Prefix:       targetPrefixIPv4.To4(),
				PrefixLength: 24,
			},
			&LDPPrefixFECValue{
				Prefix:       targetPrefixIPv4.To4(),
				PrefixLength: 24,
			},
			&LDPPrefixFECValue{
				Prefix:       targetPrefixIPv6.To16(),
				PrefixLength: 64,
			},
		},
	}

	encodedFECStackVal, err := originalFECStackVal.EncodeAsTLV()
	verifyNil(t, err)
	verifyNotNil(t, encodedFECStackVal)
	verifyEqual(t, MPLSEchoTLVTypeTargetFECStack, encodedFECStackVal.Type)

	decodedFECStackVal := &TargetFECStackValue{}
	err = decodedFECStackVal.DecodeFromTLV(encodedFECStackVal)
	verifyNil(t, err)

	verifyEqual(t, originalFECStackVal.FECs, decodedFECStackVal.FECs)
}

func TestTargetFECStackValue_EncodeStackWithInvalidFEC_Fail(t *testing.T) {
	invalidPrefixIP := net.IP{0x1, 0x0, 0x1} // Not a a valid IPv4 or IPv6 address

	targetPrefixIPv4 := net.ParseIP("104.44.1.0")
	verifyNotNil(t, targetPrefixIPv4)

	targetPrefixIPv6 := net.ParseIP("2001:db8:abcd:0012::0")
	verifyNotNil(t, targetPrefixIPv6)

	originalFECStackVal := TargetFECStackValue{
		FECs: []MPLSEchoValue{
			&LDPPrefixFECValue{
				Prefix:       targetPrefixIPv6.To16(),
				PrefixLength: 64,
			},
			&LDPPrefixFECValue{
				Prefix:       targetPrefixIPv4.To4(),
				PrefixLength: 24,
			},
			&LDPPrefixFECValue{
				Prefix:       invalidPrefixIP, // This should force the FECStackValue encoding to fail.
				PrefixLength: 1,
			},
			&LDPPrefixFECValue{
				Prefix:       targetPrefixIPv6.To16(),
				PrefixLength: 64,
			},
		},
	}

	encodedFEC, err := originalFECStackVal.EncodeAsTLV()
	verifyNil(t, encodedFEC)
	verifyNotNil(t, err)
	verifyEqual(t,
		"LDPPrefixFECValue encoding error - Prefix isn't a valid IPv4 or IPv6 address",
		err.Error())
}

func TestTargetFECStackValue_DecodeStackWithWrongTLVType_Fail(t *testing.T) {
	validFECStackVal := TargetFECStackValue{
		FECs: []MPLSEchoValue{
			&LDPPrefixFECValue{
				Prefix:       net.IP{0x1, 0x2, 0x3, 0x0},
				PrefixLength: 24,
			},
		},
	}

	encodedFECStackVal, err := validFECStackVal.EncodeAsTLV()
	verifyNil(t, err)

	// Change TLV type to the wrong one.
	encodedFECStackVal.Type = 42

	// Try to decode the bad TLV.
	decodedFECStackVal := &TargetFECStackValue{}
	err = decodedFECStackVal.DecodeFromTLV(encodedFECStackVal)
	verifyNotNil(t, err)
	verifyEqual(t,
		"TargetFECStackValue decoding error - type mismatch: expected 1, got 42",
		err.Error())
}

func TestTargetFECStackValue_DecodeStackWithInvalidSubTLV_Fail(t *testing.T) {
	validFECStackVal := TargetFECStackValue{
		FECs: []MPLSEchoValue{
			&LDPPrefixFECValue{
				Prefix:       net.IP{0x1, 0x2, 0x3, 0x0},
				PrefixLength: 24,
			},
		},
	}

	encodedFECStackVal, err := validFECStackVal.EncodeAsTLV()
	verifyNil(t, err)

	// Change sub-TLV value length to something invalid.
	encodedFECStackVal.Value[2] = 0xFF
	encodedFECStackVal.Value[3] = 0xFF

	// Try to decode the bad TLV.
	decodedFECStackVal := &TargetFECStackValue{}
	err = decodedFECStackVal.DecodeFromTLV(encodedFECStackVal)
	verifyNotNil(t, err)
	verifyEqual(t,
		"MPLSEchoTLV decoding error - TLV of type 1 goes beyond the valid data: tlvByteCountWithPadding (65540) > totalByteCount (12)",
		err.Error())
}

func TestTargetFECStackValue_DecodeStackWithInvalidLDPPrefix_Fail(t *testing.T) {
	validFECStackVal := TargetFECStackValue{
		FECs: []MPLSEchoValue{
			&LDPPrefixFECValue{
				Prefix:       net.IP{0x1, 0x2, 0x3, 0x0},
				PrefixLength: 24,
			},
		},
	}

	encodedFECStackVal, err := validFECStackVal.EncodeAsTLV()
	verifyNil(t, err)

	// Change sub-TLV value length so that it doesn't match the LDP Prefix type.
	encodedFECStackVal.Value[2] = 0x0
	encodedFECStackVal.Value[3] = 0x3

	// Try to decode the bad TLV.
	decodedFECStackVal := &TargetFECStackValue{}
	err = decodedFECStackVal.DecodeFromTLV(encodedFECStackVal)
	verifyNotNil(t, err)
	verifyEqual(t,
		"LDPPrefixFECValue decoding error - Unknown LDPPrefixFECValue type (1) or unexpected valueByteCount (3)",
		err.Error())
}

func TestTargetFECStackValue_DecodeStackWithUnknownFECType_Fail(t *testing.T) {
	validFECStackVal := TargetFECStackValue{
		FECs: []MPLSEchoValue{
			&LDPPrefixFECValue{
				Prefix:       net.IP{0x1, 0x2, 0x3, 0x0},
				PrefixLength: 24,
			},
		},
	}

	encodedFECStackVal, err := validFECStackVal.EncodeAsTLV()
	verifyNil(t, err)

	// Change sub-TLV value type to an unknown type.
	encodedFECStackVal.Value[0] = 0xFF
	encodedFECStackVal.Value[1] = 0xFF

	// Try to decode the bad TLV.
	decodedFECStackVal := &TargetFECStackValue{}
	err = decodedFECStackVal.DecodeFromTLV(encodedFECStackVal)
	verifyNotNil(t, err)
	verifyEqual(t,
		"TargetFECStackValue decoding error - unknown sub-type: 65535",
		err.Error())
}

// Define basic object validation macros.
func containsKind(kinds []reflect.Kind, kind reflect.Kind) bool {
	for i := 0; i < len(kinds); i++ {
		if kind == kinds[i] {
			return true
		}
	}

	return false
}

func isNil(object interface{}) bool {
	if object == nil {
		return true
	}

	value := reflect.ValueOf(object)
	kind := value.Kind()
	isNilableKind := containsKind(
		[]reflect.Kind{
			reflect.Chan, reflect.Func,
			reflect.Interface, reflect.Map,
			reflect.Ptr, reflect.Slice},
		kind)

	if isNilableKind && value.IsNil() {
		return true
	}

	return false
}

func verifyNotNil(t *testing.T, object interface{}) {
	if isNil(object) {
		// Get caller's file name and line number.
		_, fn, line, _ := runtime.Caller(1)
		t.Fatalf("\n[%s:%d] Expected value not to be nil", fn, line)
	}
}

func verifyNil(t *testing.T, object interface{}) {
	if !isNil(object) {
		// Get caller's file name and line number.
		_, fn, line, _ := runtime.Caller(1)
		t.Fatalf("\n[%s:%d] Expected value to be nil: %v", fn, line, object)
	}
}

func verifyTrue(t *testing.T, value bool) {
	if !value {
		// Get caller's file name and line number.
		_, fn, line, _ := runtime.Caller(1)
		t.Fatalf("\n[%s:%d] Expected value to be TRUE", fn, line)
	}
}

func verifyFalse(t *testing.T, value bool) {
	if value {
		// Get caller's file name and line number.
		_, fn, line, _ := runtime.Caller(1)
		t.Fatalf("\n[%s:%d] Expected value to be FALSE", fn, line)
	}
}

func objectsAreEqual(expected, actual interface{}) bool {
	if expected == nil || actual == nil {
		return expected == actual
	}

	exp, ok := expected.([]byte)
	if !ok {
		return reflect.DeepEqual(expected, actual)
	}

	act, ok := actual.([]byte)
	if !ok {
		return false
	}
	if exp == nil || act == nil {
		return exp == nil && act == nil
	}
	return bytes.Equal(exp, act)
}

func verifyEqual(t *testing.T, expected, actual interface{}) {
	if !objectsAreEqual(expected, actual) {
		// Get caller's file name and line number.
		_, fn, line, _ := runtime.Caller(1)
		t.Fatalf(
			"\n[%s:%d] Not equal: \nexpected: %v\nactual: %v",
			fn,
			line,
			expected,
			actual)
	}
}

func verifyLessOrEqual(t *testing.T, val1, val2 int) {
	if val1 > val2 {
		// Get caller's file name and line number.
		_, fn, line, _ := runtime.Caller(1)
		t.Fatalf(
			"\n[%s:%d] %v is not less or equal than %v",
			fn,
			line,
			val1,
			val2)
	}
}
