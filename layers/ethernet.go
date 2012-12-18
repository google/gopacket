// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package layers

import (
	"encoding/binary"
	"errors"
	"github.com/gconnell/gopacket"
)

// Ethernet is the layer for Ethernet frame headers.
type Ethernet struct {
	baseLayer
	SrcMAC, DstMAC []byte
	EthernetType   EthernetType
	// Length is only set if a length field exists within this header.  Ethernet
	// headers follow two different standards, one that uses an EthernetType, the
	// other which defines a length the follows with a LLC header (802.3).  If the
	// former is the case, we set EthernetType and Length stays 0.  In the latter
	// case, we set Length and EthernetType = EthernetTypeLLC.
	Length uint16
}

// LayerType returns LayerTypeEthernet
func (e *Ethernet) LayerType() gopacket.LayerType { return LayerTypeEthernet }

func (e *Ethernet) LinkFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointMAC, e.SrcMAC, e.DstMAC)
}

func decodeEthernet(data []byte) (out gopacket.DecodeResult, err error) {
	if len(data) < 14 {
		err = errors.New("Ethernet packet too small")
		return
	}
	eth := &Ethernet{
		DstMAC:       data[0:6],
		SrcMAC:       data[6:12],
		EthernetType: EthernetType(binary.BigEndian.Uint16(data[12:14])),
		baseLayer:    baseLayer{data[:14], data[14:]},
	}
	if eth.EthernetType < 0x0600 {
		eth.Length = uint16(eth.EthernetType)
		eth.EthernetType = EthernetTypeLLC
	}
	out.DecodedLayer = eth
	out.NextDecoder = eth.EthernetType
	out.LinkLayer = eth
	return
}
