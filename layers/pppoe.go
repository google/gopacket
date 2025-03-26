// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

// PPPoE is the layer for PPPoE encapsulation headers.
type PPPoE struct {
	BaseLayer
	Version   uint8
	Type      uint8
	Code      PPPoECode
	SessionId uint16
	Length    uint16
}

// LayerType returns gopacket.LayerTypePPPoE.
func (p *PPPoE) LayerType() gopacket.LayerType {
	return LayerTypePPPoE
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (d *PPPoE) CanDecode() gopacket.LayerClass {
	return LayerTypePPPoE
}

// // NextLayerType returns the layer type contained by this DecodingLayer.
func (d *PPPoE) NextLayerType() gopacket.LayerType {
	if d.Code == PPPoECodeSession {
		return LayerTypePPP
	}
	return gopacket.LayerTypeZero
}

// DecodeFromBytes decodes the given bytes into this layer.
func (d *PPPoE) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 6 {
		df.SetTruncated()
		return fmt.Errorf("PPPoE header with length %d too short", len(data))
	}

	d.Version = data[0] >> 4
	d.Type = data[0] & 0x0F
	d.Code = PPPoECode(data[1])
	d.SessionId = binary.BigEndian.Uint16(data[2:4])
	d.Length = binary.BigEndian.Uint16(data[4:6])
	d.BaseLayer = BaseLayer{data[:6], data[6 : 6+d.Length]}

	return nil
}

// decodePPPoE decodes the PPPoE header (see http://tools.ietf.org/html/rfc2516).
func decodePPPoE(data []byte, p gopacket.PacketBuilder) error {
	d := &PPPoE{}
	return decodingLayerDecoder(d, data, p)
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (p *PPPoE) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	payload := b.Bytes()
	bytes, err := b.PrependBytes(6)
	if err != nil {
		return err
	}
	bytes[0] = (p.Version << 4) | p.Type
	bytes[1] = byte(p.Code)
	binary.BigEndian.PutUint16(bytes[2:], p.SessionId)
	if opts.FixLengths {
		p.Length = uint16(len(payload))
	}
	binary.BigEndian.PutUint16(bytes[4:], p.Length)
	return nil
}
