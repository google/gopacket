// Copyright 2016 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
package layers

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/gopacket"
)

// vrrpPacketPriority100 is the packet:
//   06:12:21.813317 IP 192.168.0.30 > 224.0.0.18: VRRPv2, Advertisement, vrid 1, prio 100, authtype none, intvl 1s, length 20
//   	0x0000:  0100 5e00 0012 0000 5e00 0101 0800 45c0  ..^.....^.....E.
//   	0x0010:  0028 0000 0000 ff70 19cd c0a8 001e e000  .(.....p........
//   	0x0020:  0012 2101 6401 0001 ba52 c0a8 0001 0000  ..!.d....R......
//   	0x0030:  0000 0000 0000 0000 0000 0000            ............
var vrrpPacketPriority100 = []byte{
	0x01, 0x00, 0x5e, 0x00, 0x00, 0x12, 0x00, 0x00, 0x5e, 0x00, 0x01, 0x01, 0x08, 0x00, 0x45, 0xc0,
	0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0xff, 0x70, 0x19, 0xcd, 0xc0, 0xa8, 0x00, 0x1e, 0xe0, 0x00,
	0x00, 0x12, 0x21, 0x01, 0x64, 0x01, 0x00, 0x01, 0xba, 0x52, 0xc0, 0xa8, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestVRRPPacketPacket0(t *testing.T) {
	p := gopacket.NewPacket(vrrpPacketPriority100, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeVRRP}, t)

	// Version=2 Type=VRRPv2 Advertisement VirtualRtrID=1 Priority=100
	vrrp := p.Layer(LayerTypeVRRP).(*VRRPv2)
	if vrrp.Version != 2 {
		t.Fatalf("Unable to decode VRRPv2 version. Received %d, expected %d", vrrp.Version, 2)
	}

	if vrrp.Type != 1 {
		t.Fatalf("Unable to decode VRRPv2 type. Received %d, expected %d", vrrp.Type, 1)
	}

	if vrrp.Priority != 100 {
		t.Fatalf("Unable to decode VRRPv2 priority. Received %d, expected %d", vrrp.Priority, 100)
	}

	if vrrp.Checksum != 47698 {
		t.Fatalf("Unable to decode VRRPv2 checksum. Received %d, expected %d", vrrp.Checksum, 47698)
	}
}
func BenchmarkDecodeVRRPPacket0(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(vrrpPacketPriority100, LayerTypeEthernet, gopacket.NoCopy)
	}
}

// vrrpv3PacketPriority100 is the following packet:
// 19:21:41.089249 IP (tos 0xc0, ttl 255, id 82, offset 0, flags [none], proto VRRP (112), length 40)
// 10.0.0.130 > 224.0.0.18: vrrp 10.0.0.130 > 224.0.0.18: VRRPv3, Advertisement, vrid 1, prio 100, intvl 100cs, length 20, addrs(3): 192.168.200.16,192.168.200.17,192.168.200.18
// 0x0000:  0100 5e00 0012 0050 5639 0a20 0800 45c0  ..^....PV9....E.
// 0x0010:  0028 0052 0000 ff70 cfbf 0a00 0082 e000  .(.R...p........
// 0x0020:  0012 3101 6403 0064 e54e c0a8 c810 c0a8  ..1.d..d.N......
// 0x0030:  c811 c0a8 c812                           ......
var vrrpv3PacketPriority100 = []byte{
	0x01, 0x00, 0x5e, 0x00, 0x00, 0x12, 0x00, 0x50, 0x56, 0x39, 0x0a, 0x20, 0x08, 0x00, 0x45, 0xc0,
	0x00, 0x28, 0x00, 0x52, 0x00, 0x00, 0xff, 0x70, 0xcf, 0xbf, 0x0a, 0x00, 0x00, 0x82, 0xe0, 0x00,
	0x00, 0x12, 0x31, 0x01, 0x64, 0x03, 0x00, 0x64, 0xe5, 0x4e, 0xc0, 0xa8, 0xc8, 0x10, 0xc0, 0xa8,
	0xc8, 0x11, 0xc0, 0xa8, 0xc8, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestVRRPPv3acketPacket0(t *testing.T) {
	p := gopacket.NewPacket(vrrpv3PacketPriority100, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeVRRP}, t)

	// Version=3 Type=VRRPv3 Advertisement VirtualRtrID=1 Priority=100
	vrrp, ok := p.Layer(LayerTypeVRRP).(*VRRPv3)
	if !ok {
		t.Errorf("failed to assert layer type")
	}
	if vrrp.Version != 3 {
		t.Fatalf("Unable to decode VRRPv3 version. Received %d, expected %d", vrrp.Version, 3)
	}

	if vrrp.Type != 1 {
		t.Fatalf("Unable to decode VRRPv3 type. Received %d, expected %d", vrrp.Type, 1)
	}

	if vrrp.Priority != 100 {
		t.Fatalf("Unable to decode VRRPv3 priority. Received %d, expected %d", vrrp.Priority, 100)
	}

	if vrrp.Checksum != 0xe54e {
		t.Fatalf("Unable to decode VRRPv3 checksum. Received %d, expected %d", vrrp.Checksum, 0xe54e)
	}

	if vrrp.MaxAdverInt != 100 {
		t.Fatalf("Unable to decode VRRPv3 advertise interval. Received %d, expected %d", vrrp.MaxAdverInt, 100)
	}

	if vrrp.CountIPvXAddr != 3 {
		t.Fatalf("Unable to decode VRRPv3 IP addresses count. Received %d, expected %d", vrrp.CountIPvXAddr, 3)
	}

	if len(vrrp.IPvXAddress) != 3 {
		t.Fatalf("Decoded wrong number of IP address. Received %d, expected %d", len(vrrp.IPvXAddress), 3)
	}

	addresses := []net.IP{
		net.IP{192, 168, 200, 16},
		net.IP{192, 168, 200, 17},
		net.IP{192, 168, 200, 18},
	}
	for i, ip := range vrrp.IPvXAddress {
		if !bytes.Equal(ip, addresses[i]) {
			t.Fatalf("Decoded wrong IP. Recieved %s, expected %s", ip, addresses[i])
		}
	}

}

func BenchmarkDecodeVRRPv3Packet0(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(vrrpv3PacketPriority100, LayerTypeEthernet, gopacket.NoCopy)
	}
}

func TestVRRPv3Serialize(t *testing.T) {
	p := gopacket.NewPacket(vrrpv3PacketPriority100, LinkTypeEthernet, gopacket.Default)
	p.Layer(LayerTypeVRRP).(*VRRPv3).SetNetworkLayerForChecksum(p.Layer(LayerTypeIPv4).(*IPv4))
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet", p.ErrorLayer().Error())
	}
	testSerialization(t, p, vrrpv3PacketPriority100)
}
