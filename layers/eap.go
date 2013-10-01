// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
	"encoding/binary"
)

type EAPCode uint8
type EAPType uint8

const (
	EAPCodeRequest  EAPCode = 1
	EAPCodeResponse EAPCode = 2
	EAPCodeSuccess  EAPCode = 3
	EAPCodeFailure  EAPCode = 4

	// EAPTypeNone means that this EAP layer has no Type or TypeData.
	// Success and Failure EAPs will have this set.
	EAPTypeNone EAPType = 0

	EAPTypeIdentity     EAPType = 1
	EAPTypeNotification EAPType = 2
	EAPTypeNACK         EAPType = 3
	EAPTypeOTP          EAPType = 4
	EAPTypeTokenCard    EAPType = 5
)

// EAP defines an Extensible Authentication Protocol (rfc 3748) layer.
type EAP struct {
	BaseLayer
	Code     EAPCode
	Id       uint8
	Length   uint16
	Type     EAPType
	TypeData []byte
}

// LayerType returns LayerTypeEAP.
func (e *EAP) LayerType() gopacket.LayerType { return LayerTypeEAP }

// DecodeFromBytes decodes the given bytes into this layer.
func (e *EAP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	e.Code = EAPCode(data[0])
	e.Id = data[1]
	e.Length = binary.BigEndian.Uint16(data[2:4])
	if e.Length > 4 {
		e.Type = EAPType(data[4])
		e.TypeData = data[5:]
	} else {
		e.Type = 0
		e.TypeData = nil
	}
	e.BaseLayer.Contents = data[:e.Length]
	e.BaseLayer.Payload = data[e.Length:] // Should be 0 bytes
	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (e *EAP) CanDecode() gopacket.LayerClass {
	return LayerTypeEAP
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (e *EAP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func decodeEAP(data []byte, p gopacket.PacketBuilder) error {
	e := &EAP{}
	return decodingLayerDecoder(e, data, p)
}
