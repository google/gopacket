// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
	"encoding/binary"
	"errors"
	//	"fmt"
	"net"
)

// Ethernet is the layer for Ethernet frame headers.
type Ethernet struct {
	BaseLayer
	SrcMAC, DstMAC net.HardwareAddr
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

func decodeEthernet(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 14 {
		return errors.New("Ethernet packet too small")
	}
	eth := &Ethernet{
		DstMAC:       net.HardwareAddr(data[0:6]),
		SrcMAC:       net.HardwareAddr(data[6:12]),
		EthernetType: EthernetType(binary.BigEndian.Uint16(data[12:14])),
		BaseLayer:    BaseLayer{data[:14], data[14:]},
	}
	if eth.EthernetType < 0x0600 {
		eth.Length = uint16(eth.EthernetType)
		eth.EthernetType = EthernetTypeLLC
		if cmp := len(eth.Payload) - int(eth.Length); cmp < 0 {
			p.SetTruncated()
		} else if cmp > 0 {
			// Strip off bytes at the end, since we have too many bytes
			eth.Payload = eth.Payload[:len(eth.Payload)-cmp]
		}
		//	fmt.Println(eth)
	}
	p.AddLayer(eth)
	p.SetLinkLayer(eth)
	return p.NextDecoder(eth.EthernetType)
}
