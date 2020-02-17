// Copyright 2017 Google, Inc. All rights reserved.
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

const (
	cipBasePacketLen int = 2
)

var (
	// ErrCIPDataTooSmall indicates that a CIP packet has been truncated
	ErrCIPDataTooSmall = errors.New("CIP packet data truncated")
)

// CIP implements encoding/decoding for the Common Industrial Protocol, as
// defined by ODVA (odva.org).
// Refer to https://www.rockwellautomation.com/resources/downloads/rockwellautomation/pdf/sales-partners/technology-licensing/eipexp1_2.pdf
// for more information about the protocol.
type CIP struct {
	BaseLayer
	Response         bool     // false if request, true if response
	ServiceID        byte     // The service specified for the request
	ClassID          uint16   // request only
	InstanceID       uint16   // request only
	Status           byte     // Response only
	AdditionalStatus []uint16 // Response only
	Data             []byte   // Command data for request, reply data for response
}

// DecodeFromBytes unpacks a CIP packet in the `data` argument into the receiver.
func (cip *CIP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	offset := 0
	tmp := data[offset]
	offset++

	if (tmp & 0x80) == 0x80 {
		cip.Response = true
	} else {
		cip.Response = false
	}
	cip.ServiceID = tmp & 0x7f
	if !cip.Response {
		// Parse out the request
		// path size is in 16-bit words
		pathsize := data[offset]
		offset++

		if len(data) < cipBasePacketLen+int(2*pathsize) {
			df.SetTruncated()
			return ErrCIPDataTooSmall
		}

		// read the class segment
		classInfo := data[offset]
		offset++

		switch classInfo {
		case 0x20:
			// 8-bit ID
			cip.ClassID = uint16(data[offset])
			offset++
		case 0x21:
			// 16-bite ID
			cip.ClassID = binary.LittleEndian.Uint16(data[offset : offset+2])
			offset += 2
		}

		// read the instance segment
		instanceInfo := data[offset]
		offset++

		switch instanceInfo {
		case 0x24:
			// 8-bit ID
			cip.InstanceID = uint16(data[offset])
			offset++
		case 0x25:
			// 16-bite ID
			cip.InstanceID = binary.LittleEndian.Uint16(data[offset : offset+2])
			offset += 2
		}

		if offset < len(data) {
			cip.Data = data[offset:]
		}
	} else { // response
		if len(data) < cipBasePacketLen+2 {
			df.SetTruncated()
			return ErrCIPDataTooSmall
		}

		offset++ // skip the 00 padding byte

		cip.Status = data[offset]
		offset++

		additionalStatusSize := uint(data[offset])
		offset++

		if len(data) < cipBasePacketLen+2+2*int(additionalStatusSize) {
			df.SetTruncated()
			return ErrCIPDataTooSmall
		}

		for i := 0; i < int(additionalStatusSize); i++ {
			cip.AdditionalStatus = append(cip.AdditionalStatus, binary.LittleEndian.Uint16(data[offset:offset+2]))
			offset += 2
		}

		if offset < len(data) {
			cip.Data = data[offset:]
		}
	}
	return nil
}

// LayerType returns gopacket.LayerTypeCIP
func (cip *CIP) LayerType() gopacket.LayerType { return LayerTypeCIP }

// CanDecode returns gopacket.LayerTypeCIP
func (cip *CIP) CanDecode() gopacket.LayerClass { return LayerTypeCIP }

// NextLayerType returns LayerTypePayload, the only possible next
// layer type for a CIP packet.
func (cip *CIP) NextLayerType() (nl gopacket.LayerType) {
	switch {
	default:
		nl = gopacket.LayerTypePayload
	}
	return
}

func decodeCIP(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < cipBasePacketLen {
		p.SetTruncated()
		return ErrCIPDataTooSmall
	}
	cip := &CIP{}
	return decodingLayerDecoder(cip, data, p)
}
