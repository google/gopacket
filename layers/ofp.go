// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
)

// OFP layer struct
type OFP struct {
	BaseLayer
	Version uint8
	Type    uint8
	Length  uint16
	Xid     uint32
}

func (o *OFP) LayerType() gopacket.LayerType { return LayerTypeOFP }

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (o *OFP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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

// OFPGuessingDecoder attempts to guess the openflow version of the bytes it's
// given, then decode the packet accordingly.
type OFPGuessingDecoder struct{}

func (OFPGuessingDecoder) Decode(data []byte, p gopacket.PacketBuilder) error {
	switch data[0] {
	/*
		case 0x01:
			return decodeOpenflow10(data, p)
		case 0x04:
			return decodeOpenflow13(data, p)
	*/
	case 0x05:
		return decodeOFPv14(data, p)
		/*
			case 0x06:
				return decodeOpenflow15(data, p)
		*/
	}
	return errors.New("Unsupported openflow version in packet data")
}

// OFPPayloadDecoder is the decoder used to data encapsulated by each
// Openflow message. If you know that in your environment Openflow always
// have specific version, you may reset this.
var OFPPayloadDecoder gopacket.Decoder = OFPGuessingDecoder{}

func decodeOFP(data []byte, p gopacket.PacketBuilder) error {
	o := &OFP{
		Version:   data[0],
		Type:      data[1],
		Length:    binary.BigEndian.Uint16(data[2:4]),
		Xid:       binary.BigEndian.Uint32(data[4:8]),
		BaseLayer: BaseLayer{Contents: data[:8], Payload: data},
	}
	p.AddLayer(o)
	return p.NextDecoder(OFPPayloadDecoder)
}
