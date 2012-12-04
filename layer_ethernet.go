// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"errors"
)

// Ethernet is the layer for Ethernet frame headers.
type Ethernet struct {
	SrcMAC, DstMAC []byte
	EthernetType   EthernetType
}

// LayerType returns LayerTypeEthernet
func (e *Ethernet) LayerType() LayerType { return LayerTypeEthernet }

func (e *Ethernet) LinkFlow() Flow {
	return Flow{LayerTypeEthernet, string(e.SrcMAC), string(e.DstMAC)}
}

func decodeEthernet(data []byte) (out DecodeResult, err error) {
	if len(data) < 14 {
		err = errors.New("Ethernet packet too small")
		return
	}
	eth := &Ethernet{
		EthernetType: EthernetType(binary.BigEndian.Uint16(data[12:14])),
		DstMAC:       data[0:6],
		SrcMAC:       data[6:12],
	}
	out.DecodedLayer = eth
	out.RemainingBytes = data[14:]
	out.NextDecoder = eth.EthernetType
	out.LinkLayer = eth
	return
}
