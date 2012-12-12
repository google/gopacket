// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"encoding/binary"
)

// EtherIP is the struct for storing RFC 3378 EtherIP packet headers.
type EtherIP struct {
	Version  uint8
	Reserved uint16
}

// LayerType returns LayerTypeEtherIP.
func (e *EtherIP) LayerType() LayerType { return LayerTypeEtherIP }

func decodeEtherIP(data []byte) (out DecodeResult, _ error) {
	out.DecodedLayer = &EtherIP{
		Version:  data[0] >> 4,
		Reserved: binary.BigEndian.Uint16(data[:2]) & 0x0fff,
	}
	out.NextDecoder = decoderFunc(decodeEthernet)
	out.RemainingBytes = data[2:]
	return
}
