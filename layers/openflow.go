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

const (
	/* Openflow version */
	OpenflowV10 = 0x01
	OpenflowV13 = 0x04
	OpenflowV14 = 0x05
	OpenflowV15 = 0x06
)

// Openflow layer struct
type Openflow struct {
	BaseLayer
	Version uint8
	Type    uint8
	Length  uint16
	Xid     uint32
}

func (o *Openflow) LayerType() gopacket.LayerType { return LayerTypeOpenflow }

func (o *Openflow) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	o.Version = data[0]
	o.Type = data[1]
	o.Length = binary.BigEndian.Uint16(data[2:4])
	o.Xid = binary.BigEndian.Uint32(data[4:8])
	o.BaseLayer = BaseLayer{Contents: data[:8]}

	switch {
	case o.Length >= 8:
		hlen := int(o.Length)
		if hlen > len(data) {
			df.SetTruncated()
			hlen = len(data)
		}
		// Payload contains this packet data
		o.Payload = data[:hlen]
	default:
		return fmt.Errorf("Openflow packet too small: %d bytes", o.Length)
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (o *Openflow) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	payload := b.Bytes()
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}
	bytes[0] = o.Version
	bytes[1] = o.Type
	if opts.FixLengths {
		o.Length = uint16(len(payload)) + 8
	}
	binary.BigEndian.PutUint16(bytes[2:], uint16(o.Length))
	binary.BigEndian.PutUint32(bytes[4:], uint32(o.Xid))
	return nil
}

func (o *Openflow) CanDecode() gopacket.LayerClass {
	return LayerTypeOpenflow
}

func (o *Openflow) NextLayerType() gopacket.LayerType {
	switch o.Version {
	case OpenflowV14:
		return LayerTypeOpenflow14
	}
	return gopacket.LayerTypePayload
}

func decodeOpenflow(data []byte, p gopacket.PacketBuilder) error {
	ofp := &Openflow{}
	err := ofp.DecodeFromBytes(data, p)
	p.AddLayer(ofp)
	//	p.SetTransportLayer(ofp)
	if err != nil {
		return err
	}
	return p.NextDecoder(ofp.NextLayerType())
}
