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

// PPP is the layer for PPP encapsulation headers.
type PPP struct {
	BaseLayer
	PPPType       PPPType
	HasPPTPHeader bool
}

// PPPEndpoint is a singleton endpoint for PPP.  Since there is no actual
// addressing for the two ends of a PPP connection, we use a singleton value
// named 'point' for each endpoint.
var PPPEndpoint = gopacket.NewEndpoint(EndpointPPP, nil)

// PPPFlow is a singleton flow for PPP.  Since there is no actual addressing for
// the two ends of a PPP connection, we use a singleton value to represent the
// flow for all PPP connections.
var PPPFlow = gopacket.NewFlow(EndpointPPP, nil, nil)

// LayerType returns LayerTypePPP
func (p *PPP) LayerType() gopacket.LayerType { return LayerTypePPP }

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (d *PPP) CanDecode() gopacket.LayerClass {
	return LayerTypePPP
}

// // NextLayerType returns the layer type contained by this DecodingLayer.
func (d *PPP) NextLayerType() gopacket.LayerType {
	if d.PPPType == PPPTypeIPv4 {
		return LayerTypeIPv4
	}
	if d.PPPType == PPPTypeIPv6 {
		return LayerTypeIPv6
	}

	return gopacket.LayerTypeZero
}

// LinkFlow returns PPPFlow.
func (p *PPP) LinkFlow() gopacket.Flow { return PPPFlow }

// DecodeFromBytes decodes the given bytes into this layer.
func (d *PPP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 2 {
		df.SetTruncated()
		return fmt.Errorf("PPP header with length %d too short", len(data))
	}

	offset := 0
	if data[0] == 0xff && data[1] == 0x03 {
		offset = 2
		d.HasPPTPHeader = true
	}

	if len(data) < offset+2 {
		df.SetTruncated()
		return fmt.Errorf("PPP header with length %d too short", len(data))
	}

	if data[offset]&0x1 == 0 {
		if data[offset+1]&0x1 == 0 {
			return fmt.Errorf("PPP has invalid type")
		}
		d.PPPType = PPPType(binary.BigEndian.Uint16(data[offset : offset+2]))
		d.BaseLayer = BaseLayer{Contents: data[offset : offset+2], Payload: data[offset+2:]}
	} else {
		d.PPPType = PPPType(data[offset])
		d.BaseLayer = BaseLayer{Contents: data[offset : offset+1], Payload: data[offset+1:]}
	}

	return nil
}

func decodePPP(data []byte, p gopacket.PacketBuilder) error {
	d := &PPP{}
	return decodingLayerDecoder(d, data, p)
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (p *PPP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if p.PPPType&0x100 == 0 {
		bytes, err := b.PrependBytes(2)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes, uint16(p.PPPType))
	} else {
		bytes, err := b.PrependBytes(1)
		if err != nil {
			return err
		}
		bytes[0] = uint8(p.PPPType)
	}
	if p.HasPPTPHeader {
		bytes, err := b.PrependBytes(2)
		if err != nil {
			return err
		}
		bytes[0] = 0xff
		bytes[1] = 0x03
	}
	return nil
}
