// Copyright 2018 Nine Internet Solutions AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
)

// MLDv1Message represents the common structure of all MLDv1 (and MLDv2) messages
type MLDv1Message struct {
	BaseLayer
	MaximumResponseDelay uint16
	Reserved             uint16
	MulticastAddress     net.IP
}

// DecodeFromBytes decodes the given bytes into this layer.
func (m *MLDv1Message) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 20 {
		df.SetTruncated()
		return errors.New("ICMP layer less then 4 bytes for Multicast Listener Query Message V1")
	}

	m.MaximumResponseDelay = binary.BigEndian.Uint16(data[0:2])
	m.Reserved = binary.BigEndian.Uint16(data[2:4])
	m.MulticastAddress = data[4:20]

	return nil
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (*MLDv1Message) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (m *MLDv1Message) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	buf, err := b.PrependBytes(20)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint16(buf[0:], m.MaximumResponseDelay)
	binary.BigEndian.PutUint16(buf[2:], m.Reserved)
	copy(buf[4:], m.MulticastAddress)
	return nil
}

func (m *MLDv1Message) String() string {
	return fmt.Sprintf(
		"Maximum Response Delay: %d, Reserved: %x, Multicast Address: %s",
		m.MaximumResponseDelay,
		m.Reserved,
		m.MulticastAddress)
}

// MLDv1MulticastListenerQueryMessage are sent by the router to determine
// whether there are multicast listeners on the link.
// https://tools.ietf.org/html/rfc2710 Page 5
type MLDv1MulticastListenerQueryMessage struct {
	MLDv1Message
}

// LayerType returns LayerTypeMLDv1MulticastListenerQuery.
func (*MLDv1MulticastListenerQueryMessage) LayerType() gopacket.LayerType {
	return LayerTypeMLDv1MulticastListenerQuery
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (*MLDv1MulticastListenerQueryMessage) CanDecode() gopacket.LayerClass {
	return LayerTypeMLDv1MulticastListenerQuery
}

// In a Query message, the Multicast Address field is set to zero when
// sending a General Query.
// https://tools.ietf.org/html/rfc2710#section-3.6
func (m *MLDv1MulticastListenerQueryMessage) IsGeneralQuery() bool {
	return net.IPv6zero.Equal(m.MulticastAddress)
}

// In a Query message, the Multicast Address field is set to a specific
// IPv6 multicast address when sending a Multicast-Address-Specific
// Query.
// https://tools.ietf.org/html/rfc2710#section-3.6
func (m *MLDv1MulticastListenerQueryMessage) IsSpecificQuery() bool {
	return !m.IsGeneralQuery()
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (m *MLDv1MulticastListenerQueryMessage) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
  return m.MLDv1Message.SerializeTo(b, opts)
}

// MLDv1MulticastListenerReportMessage is sent by a client listening on
// a specific multicast address to indicate that it is (still) listening
// on the specific multicast address.
// https://tools.ietf.org/html/rfc2710 Page 6
type MLDv1MulticastListenerReportMessage struct {
	MLDv1Message
}

// LayerType returns LayerTypeMLDv1MulticastListenerReport.
func (*MLDv1MulticastListenerReportMessage) LayerType() gopacket.LayerType {
	return LayerTypeMLDv1MulticastListenerReport
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (*MLDv1MulticastListenerReportMessage) CanDecode() gopacket.LayerClass {
	return LayerTypeMLDv1MulticastListenerReport
}

// MLDv1MulticastListenerDoneMessage should be sent by a client when it ceases
// to listen to a multicast address on an interface.
// https://tools.ietf.org/html/rfc2710 Page 7
type MLDv1MulticastListenerDoneMessage struct {
	MLDv1Message
}

// LayerType returns LayerTypeMLDv1MulticastListenerDone.
func (*MLDv1MulticastListenerDoneMessage) LayerType() gopacket.LayerType {
	return LayerTypeMLDv1MulticastListenerDone
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (*MLDv1MulticastListenerDoneMessage) CanDecode() gopacket.LayerClass {
	return LayerTypeMLDv1MulticastListenerDone
}

func decodeMLDv1MulticastListenerReport(data []byte, p gopacket.PacketBuilder) error {
	m := &MLDv1MulticastListenerReportMessage{}
	return decodingLayerDecoder(m, data, p)
}

func decodeMLDv1MulticastListenerQuery(data []byte, p gopacket.PacketBuilder) error {
	m := &MLDv1MulticastListenerQueryMessage{}
	return decodingLayerDecoder(m, data, p)
}

func decodeMLDv1MulticastListenerDone(data []byte, p gopacket.PacketBuilder) error {
	m := &MLDv1MulticastListenerDoneMessage{}
	return decodingLayerDecoder(m, data, p)
}
