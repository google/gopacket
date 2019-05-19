// Copyright 2019 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

// This file implements the ASF RMCP payload specified in section 3.2.2.3 of
// https://www.dmtf.org/sites/default/files/standards/documents/DSP0136.pdf

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

// ASFType indicates the format of the RMCP Data block when the Enterprise
// number is set to ASF-RMCP (4542). For the purpose of open source, this is the
// only type.
type ASFType uint8

// LayerType returns the payload layer type corresponding to an ASF message
// type.
func (a ASFType) LayerType() gopacket.LayerType {
	if lt := asfClassLayerTypes[uint8(a)]; lt != 0 {
		return lt
	}

	// some layer types don't have a payload, e.g. Presence Ping.
	return gopacket.LayerTypePayload
}

func (a ASFType) String() string {
	return fmt.Sprintf("%v(%v)", uint8(a), a.LayerType())
}

var (
	asfClassLayerTypes = [255]gopacket.LayerType{
		ASFTypePresencePong: LayerTypeASFPresencePong,
	}
)

const (
	// ASFEnterprise is the IANA-assigned Enterprise Number of the ASF-RMCP
	// organisation.
	ASFEnterprise uint32 = 4542

	// ASFTypePresencePong is the message type of the response to a Presence
	// Ping message. It indicates the sender is ASF-RMCP-aware.
	ASFTypePresencePong ASFType = 0x40

	// ASFTypePresencePing is a message type sent to a managed client to solicit
	// a Presence Pong response. Clients may ignore this is the RMCP version is
	// unsupported. Sending this message with a sequence number <255 is the
	// recommended way of finding out whether an implementation sends RMCP ACKs.
	// (Super Micro does not).
	//
	// Systems implementing IPMI must respond to this ping to conform to the
	// spec, so it is a good substitute for an ICMP ping.
	ASFTypePresencePing ASFType = 0x80
)

// ASF defines ASF's generic RMCP message Data block format. See section
// 3.2.2.3.
type ASF struct {
	BaseLayer

	// Enterprise is the IANA Enterprise Number associated with the entity that
	// defines the message type. A list can be found at
	// https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers.
	// This can be thought of as the namespace for the message type. N.B.
	// network byte order.
	Enterprise uint32

	// Type is the message type, defined by the entity associated with the
	// enterprise above. No pressure, but 1 byte is the difference between
	// sending a ping and telling a machine to do an unconditional power down
	// (0x80 and 0x12 respectively).
	Type ASFType

	// Tag is the message tag, used to match request/response pairs. The tag of
	// a response is set to that of the message it is responding to. If a
	// message is not of the request/response type, this is set to 255.
	Tag uint8

	// 1 byte reserved, set to 0x00.

	// Length is the length of this layer's payload in bytes.
	Length uint8
}

// LayerType returns LayerTypeASF. It partially satisfies Layer and
// SerializableLayer.
func (*ASF) LayerType() gopacket.LayerType {
	return LayerTypeASF
}

// CanDecode returns LayerTypeASF. It partially satisfies DecodingLayer.
func (a *ASF) CanDecode() gopacket.LayerClass {
	return a.LayerType()
}

// DecodeFromBytes makes the layer represent the provided bytes. It partially
// satisfies DecodingLayer.
func (a *ASF) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 8 {
		df.SetTruncated()
		return fmt.Errorf("invalid ASF data header, length %v less than 8",
			len(data))
	}

	a.BaseLayer.Contents = data[:8]
	a.BaseLayer.Payload = data[8:]

	a.Enterprise = binary.BigEndian.Uint32(data[:4])
	a.Type = ASFType(data[4])
	a.Tag = uint8(data[5])
	// 1 byte reserved
	a.Length = uint8(data[7])
	return nil
}

// NextLayerType returns the layer type corresponding to the message type of
// this ASF data layer. This partially satisfies DecodingLayer.
func (a *ASF) NextLayerType() gopacket.LayerType {
	return a.Type.LayerType()
}

// SerializeTo writes the serialized fom of this layer into the SerializeBuffer,
// partially satisfying SerializableLayer.
func (a *ASF) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint32(bytes[:4], a.Enterprise)
	bytes[4] = uint8(a.Type)
	bytes[5] = a.Tag
	bytes[6] = 0x00
	bytes[7] = a.Length
	return nil
}

// decodeASF decodes the byte slice into an RMCP-ASF data struct.
func decodeASF(data []byte, p gopacket.PacketBuilder) error {
	return decodingLayerDecoder(&ASF{}, data, p)
}
