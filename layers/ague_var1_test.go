// Copyright 2025 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"net"
	"testing"

	"github.com/google/gopacket"
)

func logLayers(p gopacket.Packet, t *testing.T) {
	layers := p.Layers()
	t.Log("Printing packet layers")
	for _, l := range layers {
		t.Logf("  Got layer %v, %d bytes, payload of %d bytes", l.LayerType(),
			len(l.LayerContents()), len(l.LayerPayload()))
	}
	t.Log("Printing packet struct")
	t.Log(p)
	t.Log("Done printing packet struct")
}

var ethernet = Ethernet{
	SrcMAC:       net.HardwareAddr{142, 122, 18, 195, 169, 113},
	DstMAC:       net.HardwareAddr{58, 86, 107, 105, 89, 94},
	EthernetType: EthernetTypeIPv4,
}

var ipv4 = &IPv4{
	Version:  4,
	SrcIP:    net.IP{172, 16, 1, 1},
	DstIP:    net.IP{172, 16, 2, 1},
	Protocol: IPProtocolUDP,
	Flags:    IPv4DontFragment,
	TTL:      64,
	IHL:      5,
	Id:       1160,
}

var udp = &UDP{
	SrcPort: 8,
	DstPort: 666,
}

var aguevar1 = &AGUEVar1{
	Protocol: IPProtocolIPv4,
}
var innerIPv4 = &IPv4{
	Version:  4,
	SrcIP:    net.IP{172, 16, 1, 1},
	DstIP:    net.IP{172, 16, 2, 1},
	Protocol: IPProtocolICMPv4,
	Flags:    IPv4DontFragment,
	TTL:      64,
	IHL:      5,
	Id:       2238,
}

var icmpv4 = &ICMPv4{
	TypeCode: CreateICMPv4TypeCode(ICMPv4TypeEchoRequest, 0),
	Id:       4724,
	Seq:      1,
}

var ipv6 = &IPv6{
	Version:      6,
	TrafficClass: 0,
	FlowLabel:    0,
	Length:       40,
	NextHeader:   IPProtocolICMPv4,
	HopLimit:     64,
	SrcIP:        net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
	DstIP:        net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
}

var payload = gopacket.Payload{
	0xc8, 0x92, 0xa3, 0x54, 0x00, 0x00, 0x00, 0x00, 0x38, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
}

func TestIPv4OverAGUEVar1Encode(t *testing.T) {

	var xLayers = []gopacket.SerializableLayer{
		&ethernet,
		ipv4,
		udp,
		aguevar1,
		innerIPv4,
		icmpv4,
		payload,
	}

	serialBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: false, // if desired, see gre_test:setNetworkLayer()
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(serialBuf, opts, xLayers...); err != nil {
		t.Errorf("Failed to serialize packet: %v", err)
	}
	packet := gopacket.NewPacket(serialBuf.Bytes(), LinkTypeEthernet, gopacket.Default)
	if packet.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", packet.ErrorLayer().Error())
	}
	checkLayers(packet, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeUDP, LayerTypeAGUEVar1, LayerTypeIPv4, LayerTypeICMPv4, gopacket.LayerTypePayload}, t)

	// We don't have a corresponding sample packet capture, but if we did, the verify would look like this:
	// if got, want := serialBuf.Bytes(), testPacketAGUEVar1``; !reflect.DeepEqual(want, got) {
	// 	t.Errorf("Encoding mismatch, \nwant: %v\ngot %v\n", want, got)
	// }
}

func TestIPv6OverAGUEVar1Encode(t *testing.T) {

	var xLayers = []gopacket.SerializableLayer{
		&ethernet,
		ipv4,
		udp,
		aguevar1,
		ipv6,
		icmpv4,
		payload,
	}
	serialBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: false, // if desired, see gre_test:setNetworkLayer()
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(serialBuf, opts, xLayers...); err != nil {
		t.Errorf("Failed to serialize packet: %v", err)
	}
	packet := gopacket.NewPacket(serialBuf.Bytes(), LinkTypeEthernet, gopacket.Default)
	if packet.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", packet.ErrorLayer().Error())
	}
	logLayers(packet, t)
	checkLayers(packet, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeUDP, LayerTypeAGUEVar1, LayerTypeIPv6, LayerTypeICMPv4, gopacket.LayerTypePayload}, t)
}
