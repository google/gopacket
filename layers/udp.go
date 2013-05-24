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

func (udp *UDP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	udp.SrcPort = UDPPort(binary.BigEndian.Uint16(data[0:2]))
	udp.sPort = data[0:2]
	udp.DstPort = UDPPort(binary.BigEndian.Uint16(data[2:4]))
	udp.dPort = data[2:4]
	udp.Length = binary.BigEndian.Uint16(data[4:6])
	udp.Checksum = binary.BigEndian.Uint16(data[6:8])
	udp.baseLayer = baseLayer{contents: data[:8]}
	switch {
	case udp.Length >= 8:
		hlen := int(udp.Length)
		if hlen > len(data) {
			df.SetTruncated()
			hlen = len(data)
		}
		udp.payload = data[8:hlen]
	case udp.Length == 0: // Jumbogram, use entire rest of data
		udp.payload = data[8:]
	default:
		return fmt.Errorf("UDP packet too small: %d bytes", udp.Length)
	}
	return nil
}

func (u *UDP) CanDecode() gopacket.LayerClass {
	return LayerTypeUDP
}

func (u *UDP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeUDP(data []byte, p gopacket.PacketBuilder) error {
	udp := &UDP{}
	err := udp.DecodeFromBytes(data, p)
	p.AddLayer(udp)
	p.SetTransportLayer(udp)
	if err != nil {
		return err
	}
	return p.NextDecoder(gopacket.LayerTypePayload)
}

func (u *UDP) TransportFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointUDPPort, u.sPort, u.dPort)
}
