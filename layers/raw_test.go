// Copyright 2017 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"testing"

	"github.com/google/gopacket"
)

// testPacketRawICMP4 is the packet:
//   12:13:21.217957 IP 10.8.254.8 > 8.8.8.8: ICMP echo request, id 20348, seq 1, length 64
//   	0x0000:  4500 0054 1530 4000 4001 0d59 0a08 fe08  E..T.0@.@..Y....
//   	0x0010:  0808 0808 0800 d81d 4f7c 0001 e1e5 3059  ........O|....0Y
//   	0x0020:  0000 0000 fc52 0300 0000 0000 1011 1213  .....R..........
//   	0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
//   	0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233  $%&'()*+,-./0123
//   	0x0050:  3435 3637                                4567
var testPacketRawICMP4 = []byte{
	0x45, 0x00, 0x00, 0x54, 0x15, 0x30, 0x40, 0x00, 0x40, 0x01, 0x0d, 0x59, 0x0a, 0x08, 0xfe, 0x08,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0xd8, 0x1d, 0x4f, 0x7c, 0x00, 0x01, 0xe1, 0xe5, 0x30, 0x59,
	0x00, 0x00, 0x00, 0x00, 0xfc, 0x52, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
	0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
	0x34, 0x35, 0x36, 0x37,
}

func TestPacketRawIPICMPv4(t *testing.T) {
	p := gopacket.NewPacket(testPacketRawICMP4, LinkTypeRaw, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRaw, LayerTypeIPv4, LayerTypeICMPv4, gopacket.LayerTypePayload}, t)
	// If ICMPv4 is found we most likely parse at the right offset. Skip detailed tests. Just verify
	// that the Contents of the BaseLayer is an empty array
	if got, ok := p.Layer(LayerTypeRaw).(*Raw); ok {
		if len(got.BaseLayer.Contents) != 0 {
			t.Error("RAW layer not empty", len(got.BaseLayer.Contents))
		}
	} else {
		t.Error("RAW packet processing failed to get right layer")
	}
}
func BenchmarkDecodePacketRawIPICMPv4(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketRawICMP4, LinkTypeRaw, gopacket.NoCopy)
	}
}
