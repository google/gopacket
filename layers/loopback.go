// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"math/bits"

	"github.com/google/gopacket"
)

// Loopback contains the header for loopback encapsulation.  This header is
// used by both BSD and OpenBSD style loopback decoding (pcap's DLT_NULL
// and DLT_LOOP, respectively).
type Loopback struct {
	BaseLayer
	EthType EthernetType
	Family  ProtocolFamily
}

// LayerType returns LayerTypeLoopback.
func (l *Loopback) LayerType() gopacket.LayerType { return LayerTypeLoopback }

// DecodeFromBytes decodes the given bytes into this layer.
func (l *Loopback) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		return errors.New("Loopback packet too small")
	}

	// Please refer to epan/dissectors/packet-null.c and wiretap/wtap.h of Wireshark
	// project to get more details.

	if binary.BigEndian.Uint16(data) == 0xFF03 {
		return errors.New("looks like PPP in HDLC-like Framing")
	}

	nullHeader := binary.BigEndian.Uint32(data)
	if nullHeader&0xFFFF0000 != 0 {
		if nullHeader&0xFF000000 == 0 && nullHeader&0x00FF0000 < 0x00060000 {
			nullHeader >>= 16
		} else {
			nullHeader = bits.ReverseBytes32(nullHeader)
		}
	} else {
		if nullHeader&0x000000FF == 0 && nullHeader&0x0000FF00 < 0x00000600 {
			nullHeader = uint32(bits.ReverseBytes16(uint16(nullHeader & 0xFFFF)))
		}
	}

	if nullHeader > uint32(FrameMaxLenIEEE8023) {
		l.EthType = EthernetType(nullHeader)
		l.Family = ProtocolFamilyUnspec
	} else {
		l.EthType = EthernetTypeUnspec
		l.Family = ProtocolFamily(nullHeader)
	}
	l.BaseLayer = BaseLayer{data[:4], data[4:]}

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (l *Loopback) CanDecode() gopacket.LayerClass {
	return LayerTypeLoopback
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (l *Loopback) NextLayerType() gopacket.LayerType {
	if l.Family != ProtocolFamilyUnspec {
		return l.Family.LayerType()
	}
	return l.EthType.LayerType()
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (l *Loopback) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	if l.Family != ProtocolFamilyUnspec {
		binary.LittleEndian.PutUint32(bytes, uint32(l.Family))
	} else {
		binary.BigEndian.PutUint32(bytes, uint32(l.EthType))
	}
	return nil
}

func decodeLoopback(data []byte, p gopacket.PacketBuilder) error {
	l := Loopback{}
	if err := l.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}
	p.AddLayer(&l)
	if l.Family != ProtocolFamilyUnspec {
		return p.NextDecoder(l.Family)
	}
	return p.NextDecoder(l.EthType)
}
