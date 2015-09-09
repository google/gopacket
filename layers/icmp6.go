// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"reflect"
)

const (
	ICMPv6TypeDestinationUnreachable = 1
	ICMPv6TypePacketTooBig           = 2
	ICMPv6TypeTimeExceeded           = 3
	ICMPv6TypeParameterProblem       = 4
	ICMPv6TypeEchoRequest            = 128
	ICMPv6TypeEchoReply              = 129
	// The following are from RFC 4861
	ICMPv6TypeRouterSolicitation    = 133
	ICMPv6TypeRouterAdvertisement   = 134
	ICMPv6TypeNeighborSolicitation  = 135
	ICMPv6TypeNeighborAdvertisement = 136
	ICMPv6TypeRedirect              = 137
)

var (
	icmpv6TypeStringMap = map[uint8]string{
		1:   "DestinationUnreachable",
		2:   "PacketTooBig",
		3:   "TimeExceeded",
		4:   "ParameterProblem",
		128: "EchoRequest",
		129: "EchoReply",
		133: "RouterSolicitation",
		134: "RouterAdvertisement",
		135: "NeighborSolicitation",
		136: "NeighborAdvertisement",
		137: "Redirect",
	}

	icmpv6CodeStringMap = map[[2]uint8]string{
		[2]uint8{1, 0}:   "NoRouteToDst",
		[2]uint8{1, 1}:   "AdminProhibited",
		[2]uint8{1, 2}:   "BeyondScopeOfSrc",
		[2]uint8{1, 3}:   "AddressUnreachable",
		[2]uint8{1, 4}:   "PortUnreachable",
		[2]uint8{1, 5}:   "SrcAddressFailedPolicy",
		[2]uint8{1, 6}:   "RejectRouteToDst",
		[2]uint8{2, 0}:   "",
		[2]uint8{3, 0}:   "HopLimitExceeded",
		[2]uint8{3, 1}:   "FragmentReassemblyTimeExceeded",
		[2]uint8{4, 0}:   "ErroneousHeader",
		[2]uint8{4, 1}:   "UnrecognizedNextHeader",
		[2]uint8{4, 1}:   "UnrecognizedIPv6Option",
		[2]uint8{128, 0}: "",
		[2]uint8{129, 0}: "",
		[2]uint8{133, 0}: "",
		[2]uint8{134, 0}: "",
		[2]uint8{135, 0}: "",
		[2]uint8{136, 0}: "",
		[2]uint8{137, 0}: "",
	}
)

type ICMPv6TypeCode uint16

func (a ICMPv6TypeCode) Type() uint8 {
	return uint8(a >> 8)
}

func (a ICMPv6TypeCode) Code() uint8 {
	return uint8(a)
}

func (a ICMPv6TypeCode) String() string {
	tc := [2]uint8{a.Type(), a.Code()}
	typeStr, ok := icmpv6TypeStringMap[tc[0]]
	if !ok {
		return fmt.Sprintf("%d(%d)", tc[0], tc[1])
	}
	codeStr, ok := icmpv6CodeStringMap[tc]
	if !ok {
		// We don't know this ICMPv6 code; print the numerical value
		return fmt.Sprintf("%s(Code: %d)", typeStr, tc[1])
	}
	// We have a string for the ICMPv6 code. The string may be the zero
	// string (signalling the ICMPv6 code does not have any particular meaning)
	if codeStr == "" {
		return fmt.Sprintf("%s", typeStr)
	}
	return fmt.Sprintf("%s(%s)", typeStr, codeStr)
}

func (a ICMPv6TypeCode) GoString() string {
	t := reflect.TypeOf(a)
	return fmt.Sprintf("%s(%d, %d)", t.String(), a.Type(), a.Code())
}

// SerializeTo writes the ICMPv6TypeCode value to the 'bytes' buffer.
func (a ICMPv6TypeCode) SerializeTo(bytes []byte) {
	binary.BigEndian.PutUint16(bytes, uint16(a))
}

// CreateICMPv6TypeCode is a helper function to create an ICMPv6TypeCode
// gopacket type from the ICMPv6 type and code values.
func CreateICMPv6TypeCode(typ uint8, code uint8) ICMPv6TypeCode {
	return ICMPv6TypeCode(binary.BigEndian.Uint16([]byte{typ, code}))
}

// ICMPv6 is the layer for IPv6 ICMP packet data
type ICMPv6 struct {
	BaseLayer
	TypeCode  ICMPv6TypeCode
	Checksum  uint16
	TypeBytes []byte
	tcpipchecksum
}

// LayerType returns LayerTypeICMPv6.
func (i *ICMPv6) LayerType() gopacket.LayerType { return LayerTypeICMPv6 }

// DecodeFromBytes decodes the given bytes into this layer.
func (i *ICMPv6) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	i.TypeCode = CreateICMPv6TypeCode(data[0], data[1])
	i.Checksum = binary.BigEndian.Uint16(data[2:4])
	i.TypeBytes = data[4:8]
	i.BaseLayer = BaseLayer{data[:8], data[8:]}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (i *ICMPv6) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if i.TypeBytes == nil {
		i.TypeBytes = lotsOfZeros[:4]
	} else if len(i.TypeBytes) != 4 {
		return fmt.Errorf("invalid type bytes for ICMPv6 packet: %v", i.TypeBytes)
	}
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}
	i.TypeCode.SerializeTo(bytes)
	copy(bytes[4:8], i.TypeBytes)
	if opts.ComputeChecksums {
		bytes[2] = 0
		bytes[3] = 0
		csum, err := i.computeChecksum(b.Bytes(), IPProtocolICMPv6)
		if err != nil {
			return err
		}
		i.Checksum = csum
	}
	binary.BigEndian.PutUint16(bytes[2:], i.Checksum)
	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (i *ICMPv6) CanDecode() gopacket.LayerClass {
	return LayerTypeICMPv6
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (i *ICMPv6) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeICMPv6(data []byte, p gopacket.PacketBuilder) error {
	i := &ICMPv6{}
	return decodingLayerDecoder(i, data, p)
}
