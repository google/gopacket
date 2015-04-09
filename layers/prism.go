// Copyright 2015 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// http://www.tcpdump.org/linktypes/LINKTYPE_IEEE802_11_PRISM.html

package layers

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
)

func decodePrismValue(data []byte, pv *PrismValue) {
	pv.DID = PrismDID(binary.LittleEndian.Uint32(data[0:4]))
	pv.Status = binary.LittleEndian.Uint16(data[4:6])
	pv.Length = binary.LittleEndian.Uint16(data[6:8])
	pv.Data = binary.LittleEndian.Uint32(data[8:12])
}

type PrismDID uint32

const (
	PrismHostTime                  PrismDID = 0x1041
	PrismMACTime                   PrismDID = 0x2041
	PrismChannel                   PrismDID = 0x3041
	PrismRSSI                      PrismDID = 0x4041
	PrismSignalQuality             PrismDID = 0x5041
	PrismSignal                    PrismDID = 0x6041
	PrismNoise                     PrismDID = 0x7041
	PrismRate                      PrismDID = 0x8041
	PrismTransmittedFrameIndicator PrismDID = 0x9041
	PrismFrameLength               PrismDID = 0xA041
)

type PrismValue struct {
	DID    PrismDID
	Status uint16
	Length uint16
	Data   uint32
}

var ErrPrismExpectedMoreData = errors.New("Expected more data.")

func decodePrismHeader(data []byte, p gopacket.PacketBuilder) error {
	d := &PrismHeader{}
	return decodingLayerDecoder(d, data, p)
}

type PrismHeader struct {
	BaseLayer
	Code       uint16
	Length     uint16
	DeviceName string
	Values     []PrismValue
}

func (m *PrismHeader) LayerType() gopacket.LayerType { return LayerTypePrismHeader }

func (m *PrismHeader) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	m.Code = binary.LittleEndian.Uint16(data[0:4])
	m.Length = binary.LittleEndian.Uint16(data[4:8])
	m.DeviceName = string(data[8:24])
	m.BaseLayer = BaseLayer{Contents: data[:m.Length], Payload: data[m.Length:len(data)]}

	offset := uint16(24)

	m.Values = make([]PrismValue, (m.Length-offset)/12)
	for i := 0; i < len(m.Values); i++ {
		decodePrismValue(data[offset:offset+12], &m.Values[i])
		offset += 12
	}

	if offset != m.Length {
		return ErrPrismExpectedMoreData
	}

	return nil
}

func (m *PrismHeader) CanDecode() gopacket.LayerClass    { return LayerTypePrismHeader }
func (m *PrismHeader) NextLayerType() gopacket.LayerType { return LayerTypeDot11 }
