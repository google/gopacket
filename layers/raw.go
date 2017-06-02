// Copyright 2012 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"github.com/google/gopacket"
)

// RawIP (DLT_RAW) contains no header and we start with the IP header
type Raw struct {
	BaseLayer
	Family ProtocolFamily
}

func (r *Raw) LayerType() gopacket.LayerType { return LayerTypeRaw }

func (r *Raw) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 1 {
		return fmt.Errorf("Raw packet too small")
	}

	family, err := versionToFamily(data[0] >> 4)
	if err != nil {
		return err
	}
	r.Family = family
	r.BaseLayer = BaseLayer{make([]byte, 0), data}
	return nil
}

func (r *Raw) CanDecode() gopacket.LayerClass {
	return LayerTypeRaw
}

func (r *Raw) NextLayerType() gopacket.LayerType {
	return r.Family.LayerType()
}

func versionToFamily(version uint8) (ProtocolFamily, error) {
	switch version {
	case 4:
		return ProtocolFamilyIPv4, nil
	case 6:
		return ProtocolFamilyIPv6Linux, nil
	default:
		return 0, fmt.Errorf("Unknown protocol version %d", version)
	}
}

// Decode a raw v4 or v6 IP packet.
func decodeRawIP(data []byte, p gopacket.PacketBuilder) error {
	family, err := versionToFamily(data[0] >> 4)
	if err != nil {
		return err
	}
	r := &Raw{
		BaseLayer: BaseLayer{make([]byte, 0), data},
		Family:    family,
	}
	p.AddLayer(r)
	return p.NextDecoder(r.Family)
}
