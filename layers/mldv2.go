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

const (
  // S Flag bit is 1
  sTrue uint8 = 0x8

  // S Flag value mask
  //   sTrue & sMask == sTrue  // true
  //   0x1   & sMask == sTrue  // true
  //   0x0   & sMask == sTrue  // false
  sMask uint8 = 0x8

  // QRV value mask
  qrvMask uint8 = 0x7
)

// MLDv2MulticastListenerQueryMessage are sent by multicast routers to query the
// multicast listening state of neighboring interfaces.
// https://tools.ietf.org/html/rfc3810#section-5.1
//
// Some information, like Maximum Response Code and Multicast Address are in the
// previous layer LayerTypeMLDv1MulticastListenerQuery
type MLDv2MulticastListenerQueryMessage struct {
  BaseLayer
  // 5.1.7. S Flag (Suppress Router-Side Processing)
  S bool
  // 5.1.8. QRV (Querier's Robustness Variable)
  QRV uint8
  // 5.1.9. QQIC (Querier's Query Interval Code)
  QQIC uint8
  QQI time.Duration
  // 5.1.10. Number of Sources (N)
  N uint16
  // 5.1.11 Source Address [i]
  SourceAddresses []net.IP
}

// DecodeFromBytes decodes the given bytes into this layer.
func (m *MLDv2MulticastListenerQueryMessage) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
  if len(data) < 4 {
    df.SetTruncated()
    return errors.New("Multicast Listener Query Message V1 layer less than 4 bytes for Multicast Listener Query Message V2")
  }

  m.S = (data[0] & sMask) == sTrue
  m.QRV = data[0] & qrvMask
  m.QQIC = data[1]
  m.QQI = qqicToQQI(data[1])

  m.N = binary.BigEndian.Uint16(data[2:4])

  for i := uint16(0); i < m.N; i++ {
    begin := 4 + (int(i) * 16)
    end := begin + 16

    if end > len(data) {
      df.SetTruncated()
      return fmt.Errorf("ICMP layer less than %d bytes for Multicast Listener Query Message V2", end)
    }

    m.SourceAddresses = append(m.SourceAddresses, data[begin:end])
  }

  return nil
}

// calculation according to https://tools.ietf.org/html/rfc3810#section-5.1.9
func qqicToQQI(data byte) time.Duration {
  if data < 128 {
    return time.Second * time.Duration(data)
  }

  exp := uint16(data) & 0x70 >> 4
  mant := uint16(data) & 0x0F
  return time.Second * time.Duration(mant|0x1000<<(exp+3))
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (*MLDv2MulticastListenerQueryMessage) NextLayerType() gopacket.LayerType {
  return gopacket.LayerTypePayload
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (m *MLDv2MulticastListenerQueryMessage) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
  if err := m.serializeSourceAddressesTo(b, opts); err != nil {
    return err
  }

  buf, err := b.PrependBytes(4)
  if err != nil {
    return err
  }

  binary.BigEndian.PutUint16(buf[2:4], m.N)

  if m.QQIC != 0 {
    buf[1] = m.QQIC
  } else {
    buf[1] = qqiToQQIC(m.QQI)
  }

  byte0 := m.QRV & qrvMask
  if m.S {
    byte0 |= sTrue
  } else {
    byte0 &= 0xF7 // 0xF7 is the inverse of sTrue=0x08
  }
  byte0 ^= 0x1F // set reserved bytes to zero
  buf[0] = byte0

  return nil
}

// calculation according to https://tools.ietf.org/html/rfc3810#section-5.1.9
func qqiToQQIC(d time.Duration) uint8 {
  if d <= 0 {
    return 0
  }

  dms := d / time.Second
  if dms < 128 {
    return uint8(dms)
  }

  if dms > 31744 { // mant=0xF, exp=0x7
    return 0xFF
  }

  value := uint16(dms) // ok, because 31744 < math.MaxUint16
  exp := uint8(7)
  for mask := uint16(0x4000); exp > 0; exp-- {
    if mask&value != 0 {
      break
    }

    mask >>= 1
  }

  mant := uint8(0x000F & (value >> (exp + 3)))
  sig := uint8(0x10)
  return sig | exp<<4 | mant
}

// writes each source address to the buffer preserving the order
func (m *MLDv2MulticastListenerQueryMessage) serializeSourceAddressesTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
  numberOfSourceAddresses := len(m.SourceAddresses)
  if numberOfSourceAddresses > math.MaxUint16 {
    return fmt.Errorf(
      "there are more than %d source addresses, but 65535 is the maximum number of supported addresses",
      numberOfSourceAddresses)
  }

  if opts.FixLengths {
    m.N = uint16(numberOfSourceAddresses)
  }

  lastSAIdx := numberOfSourceAddresses - 1
  for k := range m.SourceAddresses {
    i := lastSAIdx - k // reverse order

    buf, err := b.PrependBytes(16)
    if err != nil {
      return err
    }

    copy(buf[0:], m.SourceAddresses[i].To16())
  }

  return nil
}

func (m *MLDv2MulticastListenerQueryMessage) String() string {
  return fmt.Sprintf(
    "S Flag: %t, QRV: %#x, QQI: %ds (Code: %#x), Number of Source Address: %d (actual: %d), Source Addresses: %s",
    m.S,
    m.QRV,
    m.QQI / time.Second,
    m.QQIC,
    m.N,
    len(m.SourceAddresses),
    m.SourceAddresses)
}

// LayerType returns LayerTypeMLDv2MulticastListenerQuery.
func (*MLDv2MulticastListenerQueryMessage) LayerType() gopacket.LayerType {
  return LayerTypeMLDv2MulticastListenerQuery
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (*MLDv2MulticastListenerQueryMessage) CanDecode() gopacket.LayerClass {
  return LayerTypeMLDv2MulticastListenerQuery
}

// MLDv2MulticastListenerReportMessage is sent by an IP node to report the
// current multicast listening state, or changes therein.
// https://tools.ietf.org/html/rfc3810#section-5.2
type MLDv2MulticastListenerReportMessage struct {
  BaseLayer
  // 5.2.3. Nr of Mcast Address Records
  M uint16
  // 5.2.4. Multicast Address Record [i]
  MulticastAddressRecords []MLDv2MulticastAddressRecord
}

// DecodeFromBytes decodes the given bytes into this layer.
func (m *MLDv2MulticastListenerReportMessage) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
  if len(data) < 4 {
    df.SetTruncated()
    return errors.New("ICMP layer less than 4 bytes for Multicast Listener Report Message V2")
  }

  // ignore data[0:2] as per RFC
  // https://tools.ietf.org/html/rfc3810#section-5.2.1
  m.M = binary.BigEndian.Uint16(data[2:4])

  begin := 4
  for i := uint16(0); i < m.M; i++ {
    mar := MLDv2MulticastAddressRecord{}
    read, err := mar.decode(data[begin:], df)
    if err != nil {
      return err
    }

    m.MulticastAddressRecords = append(m.MulticastAddressRecords, mar)

    begin += read
  }

  return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (m *MLDv2MulticastListenerReportMessage) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
  lastItemIdx := len(m.MulticastAddressRecords) - 1
  for k := range m.MulticastAddressRecords {
    i := lastItemIdx - k // reverse order

    err := m.MulticastAddressRecords[i].serializeTo(b, opts)
    if err != nil {
      return err
    }
  }

  if opts.FixLengths {
    numberOfMAR := len(m.MulticastAddressRecords)
    if numberOfMAR > math.MaxUint16 {
      return fmt.Errorf(
        "%d multicast address records added, but the maximum is 65535",
        numberOfMAR)
    }

    m.M = uint16(numberOfMAR)
  }

  buf, err := b.PrependBytes(4)
  if err != nil {
    return err
  }

  copy(buf[0:2], []byte{0x0, 0x0})
  binary.BigEndian.PutUint16(buf[2:4], m.M)
  return nil
}

func (m *MLDv2MulticastListenerReportMessage) String() string {
  return fmt.Sprintf(
    "M: %d, Multicast Address Records: %+v",
    m.M,
    m.MulticastAddressRecords)
}

// LayerType returns LayerTypeMLDv2MulticastListenerQuery.
func (*MLDv2MulticastListenerReportMessage) LayerType() gopacket.LayerType {
  return LayerTypeMLDv2MulticastListenerReport
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (*MLDv2MulticastListenerReportMessage) CanDecode() gopacket.LayerClass {
  return LayerTypeMLDv2MulticastListenerReport
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (*MLDv2MulticastListenerReportMessage) NextLayerType() gopacket.LayerType {
  return gopacket.LayerTypePayload
}

const (
  // MODE_IS_INCLUDE - indicates that the interface has a filter
  // mode of INCLUDE for the specified multicast address.
  MLDv2MulticastAddressRecordTypeModeIsIncluded = 1
  // MODE_IS_EXCLUDE - indicates that the interface has a filter
  // mode of EXCLUDE for the specified multicast address.
  MLDv2MulticastAddressRecordTypeModeIsExcluded = 2
  // CHANGE_TO_INCLUDE_MODE - indicates that the interface has
  // changed to INCLUDE filter mode for the specified multicast
  // address.
  MLDv2MulticastAddressRecordTypeChangeToIncludeMode = 3
  // CHANGE_TO_EXCLUDE_MODE - indicates that the interface has
  // changed to EXCLUDE filter mode for the specified multicast
  // address
  MLDv2MulticastAddressRecordTypeChangeToExcludeMode = 4
  // ALLOW_NEW_SOURCES - indicates that the Source Address [i]
  // fields in this Multicast Address Record contain a list of
  // the additional sources that the node wishes to listen to,
  // for packets sent to the specified multicast address.
  MLDv2MulticastAddressRecordTypeAllowNewSources = 5
  // BLOCK_OLD_SOURCES - indicates that the Source Address [i]
  // fields in this Multicast Address Record contain a list of
  // the sources that the node no longer wishes to listen to,
  // for packets sent to the specified multicast address.
  MLDv2MulticastAddressRecordTypeBlockOldSources = 6
)

// MLDv2MulticastAddressRecord contains information on the sender listening to a
// single multicast address on the interface the report is sent.
// https://tools.ietf.org/html/rfc3810#section-5.2.4
type MLDv2MulticastAddressRecord struct {
  // 5.2.5. Record Type
  RecordType uint8
  // 5.2.6. Auxiliary Data Length in 32-bit words
  AuxDataLen uint8
  // 5.2.7. Number Of Sources (N)
  N uint16
  // 5.2.8. Multicast Address
  MulticastAddress net.IP
  // 5.2.9 Source Address [i]
  SourceAddresses []net.IP
  // 5.2.10 Auxiliary Data
  AuxiliaryData []byte
}

// decodes a multicast address record from bytes
func (m *MLDv2MulticastAddressRecord) decode(data []byte, df gopacket.DecodeFeedback) (int, error) {
  if len(data) < 4 {
    df.SetTruncated()
    return 0, errors.New(
      "Multicast Listener Report Message V2 layer less than 4 bytes for Multicast Address Record")
  }

  m.RecordType = data[0]
  m.AuxDataLen = data[1]
  m.N = binary.BigEndian.Uint16(data[2:4])
  m.MulticastAddress = data[4:20]

  for i := uint16(0); i < m.N; i++ {
    begin := 20 + (int(i) * 16)
    end := begin + 16

    if len(data) < end {
      df.SetTruncated()
      return begin, fmt.Errorf(
        "Multicast Listener Report Message V2 layer less than %d bytes for Multicast Address Record", end)
    }

    m.SourceAddresses = append(m.SourceAddresses, data[begin:end])
  }

  expectedLengthWithouAuxData := 20 + (int(m.N) * 16)
  expectedTotalLength := (int(m.AuxDataLen) * 4) + expectedLengthWithouAuxData // *4 because AuxDataLen are 32bit words
  if len(data) < expectedTotalLength {
    return expectedLengthWithouAuxData, fmt.Errorf(
      "Multicast Listener Report Message V2 layer less than %d bytes for Multicast Address Record",
      expectedLengthWithouAuxData)
  }

  m.AuxiliaryData = data[expectedLengthWithouAuxData:expectedTotalLength]

  return expectedTotalLength, nil
}

func (m *MLDv2MulticastAddressRecord) String() string {
  return fmt.Sprintf(
    "RecordType: %d (%s), AuxDataLen: %d [32-bit words], N: %d, Multicast Address: %s, SourceAddresses: %s, Auxiliary Data: %#x",
    m.RecordType,
    m.RecordTypeString(),
    m.AuxDataLen,
    m.N,
    m.MulticastAddress.To16(),
    m.SourceAddresses,
    m.AuxiliaryData)
}

// Human readable record type
// Naming follows https://tools.ietf.org/html/rfc3810#section-5.2.12
func (m *MLDv2MulticastAddressRecord) RecordTypeString() string {
  switch m.RecordType {
  case MLDv2MulticastAddressRecordTypeModeIsIncluded:
    return "MODE_IS_INCLUDE"
  case MLDv2MulticastAddressRecordTypeModeIsExcluded:
    return "MODE_IS_EXCLUDE"
  case MLDv2MulticastAddressRecordTypeChangeToIncludeMode:
    return "CHANGE_TO_INCLUDE_MODE"
  case MLDv2MulticastAddressRecordTypeChangeToExcludeMode:
    return "CHANGE_TO_EXCLUDE_MODE"
  case MLDv2MulticastAddressRecordTypeAllowNewSources:
    return "ALLOW_NEW_SOURCES"
  case MLDv2MulticastAddressRecordTypeBlockOldSources:
    return "BLOCK_OLD_SOURCES"
  default:
    return fmt.Sprintf("UNKNOWN(%d)", m.RecordType)
  }
}

// serializes a multicast address record
func (m *MLDv2MulticastAddressRecord) serializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
  if err := m.serializeAuxiliaryDataTo(b, opts); err != nil {
    return err
  }

  if err := m.serializeSourceAddressesTo(b, opts); err != nil {
    return err
  }

  buf, err := b.PrependBytes(20)
  if err != nil {
    return err
  }

  buf[0] = m.RecordType
  buf[1] = m.AuxDataLen
  binary.BigEndian.PutUint16(buf[2:4], m.N)
  copy(buf[4:], m.MulticastAddress)

  return nil
}

// serializes the auxiliary data of a multicast address record
func (m *MLDv2MulticastAddressRecord) serializeAuxiliaryDataTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
  if remainder := len(m.AuxiliaryData) % 4; remainder != 0 {
    zeroWord := []byte{0x0, 0x0, 0x0, 0x0}
    m.AuxiliaryData = append(m.AuxiliaryData, zeroWord[:remainder]...)
  }

  if opts.FixLengths {
    auxDataLen := len(m.AuxiliaryData) / 4

    if auxDataLen > math.MaxUint8 {
      return fmt.Errorf("auxilary data is %d 32-bit words, but the maximum is 255 32-bit words", auxDataLen)
    }

    m.AuxDataLen = uint8(auxDataLen)
  }

  buf, err := b.PrependBytes(len(m.AuxiliaryData))
  if err != nil {
    return err
  }

  copy(buf, m.AuxiliaryData)
  return nil
}

// serializes the source addresses of a multicast address record preserving the order
func (m *MLDv2MulticastAddressRecord) serializeSourceAddressesTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
  if opts.FixLengths {
    numberOfSourceAddresses := len(m.SourceAddresses)

    if numberOfSourceAddresses > math.MaxUint16 {
      return fmt.Errorf(
        "%d source addresses added, but the maximum is 65535",
        numberOfSourceAddresses)
    }

    m.N = uint16(numberOfSourceAddresses)
  }

  lastItemIdx := len(m.SourceAddresses) - 1
  for k := range m.SourceAddresses {
    i := lastItemIdx - k // reverse order

    buf, err := b.PrependBytes(16)
    if err != nil {
      return err
    }
    copy(buf, m.SourceAddresses[i])
  }

  return nil
}

func decodeMLDv2MulticastListenerReport(data []byte, p gopacket.PacketBuilder) error {
  m := &MLDv2MulticastListenerReportMessage{}
  return decodingLayerDecoder(m, data, p)
}

func decodeMLDv2MulticastListenerQuery(data []byte, p gopacket.PacketBuilder) error {
  m := &MLDv2MulticastListenerQueryMessage{}
  return decodingLayerDecoder(m, data, p)
}
