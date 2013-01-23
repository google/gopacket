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
	"fmt"
)

// UDP is the layer for UDP headers.
type UDP struct {
	baseLayer
	SrcPort, DstPort UDPPort
	Length           uint16
	Checksum         uint16
	sPort, dPort     []byte
}

// LayerType returns gopacket.LayerTypeUDP
func (u *UDP) LayerType() gopacket.LayerType { return LayerTypeUDP }

func decodeUDP(data []byte, p gopacket.PacketBuilder) error {
	udp := &UDP{
		SrcPort:   UDPPort(binary.BigEndian.Uint16(data[0:2])),
		sPort:     data[0:2],
		DstPort:   UDPPort(binary.BigEndian.Uint16(data[2:4])),
		dPort:     data[2:4],
		Length:    binary.BigEndian.Uint16(data[4:6]),
		Checksum:  binary.BigEndian.Uint16(data[6:8]),
		baseLayer: baseLayer{contents: data[:8]},
	}
	switch {
	case udp.Length >= 8:
		hlen := int(udp.Length)
		if hlen > len(data) {
			p.SetTruncated()
			hlen = len(data)
		}
		udp.payload = data[8:hlen]
	case udp.Length == 0: // Jumbogram, use entire rest of data
		udp.payload = data[8:]
	default:
		return fmt.Errorf("UDP packet too small: %d bytes", udp.Length)
	}
	p.AddLayer(udp)
	p.SetTransportLayer(udp)
	return p.NextDecoder(gopacket.LayerTypePayload)
}

func (u *UDP) TransportFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointUDPPort, u.sPort, u.dPort)
}
