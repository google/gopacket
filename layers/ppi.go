// Copyright 2025 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// http://www.tcpdump.org/linktypes/LINKTYPE_PPI.html

package layers

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
)

const ppiCommonHeaderLength = 8

var (
	errPPITruncated      = errors.New("PPI header too small")
	errPPIInvalidVersion = errors.New("PPI version must be 0")
	errPPIInvalidLength  = errors.New("PPI header length invalid")
)

// PPI is a skip-through decoder for LINKTYPE_PPI (192).
// Only BaseLayer is exported so this can be extended later without a
// backwards-incompatible API change.
type PPI struct {
	BaseLayer
	version uint8
	flags   uint8
	length  uint16
	dlt     uint32
}

func (ppi *PPI) LayerType() gopacket.LayerType { return LayerTypePPI }

func (ppi *PPI) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < ppiCommonHeaderLength {
		df.SetTruncated()
		return errPPITruncated
	}
	ppi.version = data[0]
	ppi.flags = data[1]
	ppi.length = binary.LittleEndian.Uint16(data[2:4])
	ppi.dlt = binary.LittleEndian.Uint32(data[4:8])
	if ppi.version != 0 {
		return errPPIInvalidVersion
	}
	if ppi.length < ppiCommonHeaderLength || int(ppi.length) > len(data) {
		if int(ppi.length) > len(data) {
			df.SetTruncated()
		}
		return errPPIInvalidLength
	}
	ppi.BaseLayer = BaseLayer{Contents: data[:ppi.length], Payload: data[ppi.length:]}
	return nil
}

func (ppi *PPI) CanDecode() gopacket.LayerClass { return LayerTypePPI }

func (ppi *PPI) NextLayerType() gopacket.LayerType {
	if ppi.dlt > 0xff {
		return gopacket.LayerTypeZero
	}
	switch LinkType(ppi.dlt) {
	case LinkTypeEthernet:
		return LayerTypeEthernet
	case LinkTypeIEEE802_11:
		return LayerTypeDot11
	case LinkTypeIEEE80211Radio:
		return LayerTypeRadioTap
	default:
		return gopacket.LayerTypeZero
	}
}

func decodePPI(data []byte, p gopacket.PacketBuilder) error {
	d := &PPI{}
	return decodingLayerDecoder(d, data, p)
}
