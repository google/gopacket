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
	"math"
	"net"
	"time"

	"github.com/google/gopacket"
)

// MLDv1Message represents the common structure of all MLDv1 messages
type MLDv1Message struct {
	BaseLayer
	// 3.4. Maximum Response Delay
	// In milliseconds
	// See also MLDv2MaximumResponseCode for Query Messages
	MaximumResponseDelay time.Duration
	// for MLDv2
	maximumResponseDelayBytes uint16
	// 3.6. Multicast Address
	// Zero in general query
	// Specific IPv6 multicast address otherwise
	MulticastAddress     net.IP
}

// DecodeFromBytes decodes the given bytes into this layer.
func (m *MLDv1Message) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 20 {
		df.SetTruncated()
		return errors.New("ICMP layer less than 20 bytes for Multicast Listener Query Message V1")
	}

	m.maximumResponseDelayBytes = binary.BigEndian.Uint16(data[0:2])
	m.MaximumResponseDelay = time.Duration(m.maximumResponseDelayBytes)
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

	if m.maximumResponseDelayBytes == 0 && m.MaximumResponseDelay > 0 {
		maxRespDelay := m.MaximumResponseDelay / time.Millisecond

		if maxRespDelay > math.MaxUint16 {
			return fmt.Errorf(
				"maximum response delay is 65535ms, but %dms given", maxRespDelay)
		}

		m.maximumResponseDelayBytes = uint16(maxRespDelay)
	}

	binary.BigEndian.PutUint16(buf[0:4], m.maximumResponseDelayBytes)

	copy(buf[4:], m.MulticastAddress)
	return nil
}

func (m *MLDv1Message) String() string {
	return fmt.Sprintf(
		"Maximum Response Delay: %dms, Multicast Address: %s",
		m.MaximumResponseDelay,
		m.MulticastAddress)
}

// MLDv1MulticastListenerQueryMessage are sent by the router to determine
// whether there are multicast listeners on the link.
// https://tools.ietf.org/html/rfc2710 Page 5
type MLDv1MulticastListenerQueryMessage struct {
	MLDv1Message
	hasV2Content bool
}

func (m *MLDv1MulticastListenerQueryMessage) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	err := m.MLDv1Message.DecodeFromBytes(data, df)
	if err != nil {
		return err
	}

	if len(data) > 20 {
		m.hasV2Content = true
		m.Payload = data[20:]
	}

	return nil
}

func (m *MLDv1MulticastListenerQueryMessage) String() string {
	var duration time.Duration

	if !m.hasV2Content {
		duration = m.MaximumResponseDelay
	} else {
		duration = m.MLDv2MaximumResponseDelay()
	}

	return fmt.Sprintf(
		"Maximum Response Delay: %dms (Code: %#x), Multicast Address: %s",
		duration,
		m.maximumResponseDelayBytes,
		m.MulticastAddress)
}

// LayerType returns LayerTypeMLDv1MulticastListenerQuery.
func (*MLDv1MulticastListenerQueryMessage) LayerType() gopacket.LayerType {
	return LayerTypeMLDv1MulticastListenerQuery
}

// LayerType returns LayerTypeMLDv1MulticastListenerQuery.
func (m *MLDv1MulticastListenerQueryMessage) NextLayerType() gopacket.LayerType {
	if m.hasV2Content {
		return LayerTypeMLDv2MulticastListenerQuery
	}
	return gopacket.LayerTypePayload
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

// Returns the Maximum Response Delay according to MLDv2
// https://tools.ietf.org/html/rfc3810#section-5.1.3
func (m *MLDv1MulticastListenerQueryMessage) MLDv2MaximumResponseDelay() time.Duration {
	if m.maximumResponseDelayBytes < 0x8000 {
		return time.Millisecond * m.MaximumResponseDelay
	}

	exp := m.maximumResponseDelayBytes & 0x7000 >> 12
	mant := m.maximumResponseDelayBytes & 0x0FFF

	return time.Millisecond * time.Duration(mant|0x1000<<(exp+3))
}

func maxRespDelayToMaxRespCode(d time.Duration) uint16 {
	if d <= 0 {
		return 0
	}

	dms := d / time.Millisecond

	if dms < 32768 {
		return uint16(dms)
	}

	if dms > 4193280 { // mant=0xFFF, exp=0x7
		return 0xFFFF
	}

	value := uint32(dms) // ok, because 4193280 < math.MaxUint32
	exp := uint8(7)
	for mask := uint32(0x40000000); exp > 0; exp-- {
		if mask&value != 0 {
			break
		}

		mask >>= 1
	}

	mant := uint16(0x00000FFF & (value >> (exp + 3)))
	sig := uint16(0x1000)
	return sig | uint16(exp)<<12 | mant
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (m *MLDv1MulticastListenerQueryMessage) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if len(b.Bytes()) > 0 {
		// MLDv2 content already in the buffer
		m.hasV2Content = true
		m.maximumResponseDelayBytes = maxRespDelayToMaxRespCode(m.MaximumResponseDelay)
	}
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
