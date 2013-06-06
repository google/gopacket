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

// EtherIP is the struct for storing RFC 3378 EtherIP packet headers.
type EtherIP struct {
	BaseLayer
	Version  uint8
	Reserved uint16
}

// LayerType returns gopacket.LayerTypeEtherIP.
func (e *EtherIP) LayerType() gopacket.LayerType { return LayerTypeEtherIP }

func decodeEtherIP(data []byte, p gopacket.PacketBuilder) error {
	p.AddLayer(&EtherIP{
		Version:   data[0] >> 4,
		Reserved:  binary.BigEndian.Uint16(data[:2]) & 0x0fff,
		BaseLayer: BaseLayer{data[:2], data[2:]},
	})
	return p.NextDecoder(LayerTypeEthernet)
}
