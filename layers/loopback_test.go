// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
package layers

import (
	"reflect"
	"testing"

	"github.com/google/gopacket"
)

// Frame 1: 64 bytes on wire (512 bits), 64 bytes captured (512 bits)
// Null/Loopback
//     Type: IPv4 (0x0800)
// Internet Protocol Version 4, Src: 10.134.230.125 (10.134.230.125), Dst: 64.233.187.188 (64.233.187.188)
// Transmission Control Protocol, Src Port: 46769, Dst Port: 5228, Seq: 368808644, Len: 0
var testPacketLoopbackType = []byte{
	0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x3c, 0xde, 0x11, 0x40, 0x00, 0x40, 0x06, 0x6f, 0x01,
	0x0a, 0x86, 0xe6, 0x7d, 0x40, 0xe9, 0xbb, 0xbc, 0xb6, 0xb1, 0x14, 0x6c, 0x15, 0xfb, 0x92, 0xc4,
	0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xff, 0xff, 0x99, 0xf0, 0x00, 0x00, 0x02, 0x04, 0x05, 0x64,
	0x04, 0x02, 0x08, 0x0a, 0x00, 0x03, 0x4c, 0xd5, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x08,
}

func TestPacketLoopbackType(t *testing.T) {
	p := gopacket.NewPacket(testPacketLoopbackType, LayerTypeLoopback, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeLoopback, LayerTypeIPv4, LayerTypeTCP}, t)
	checkSerialization(p, t)
	if got, ok := p.Layer(LayerTypeLoopback).(*Loopback); ok {
		want := &Loopback{
			BaseLayer: BaseLayer{
				Contents: testPacketLoopbackType[:4],
				Payload:  testPacketLoopbackType[4:],
			},
			EthType: EthernetTypeIPv4,
			Family:  ProtocolFamilyUnspec,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Loopback packet processing failed:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No Loopback layer type found in packet")
	}
}

// Frame 1: 64 bytes on wire (512 bits), 64 bytes captured (512 bits)
// Null/Loopback
//     Family: IP (2)
// Internet Protocol Version 4, Src: 10.134.230.125 (10.134.230.125), Dst: 64.233.187.188 (64.233.187.188)
// Transmission Control Protocol, Src Port: 46769, Dst Port: 5228, Seq: 368808644, Len: 0
var testPacketLoopbackFamily = []byte{
	0x02, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x3c, 0xde, 0x11, 0x40, 0x00, 0x40, 0x06, 0x6f, 0x01,
	0x0a, 0x86, 0xe6, 0x7d, 0x40, 0xe9, 0xbb, 0xbc, 0xb6, 0xb1, 0x14, 0x6c, 0x15, 0xfb, 0x92, 0xc4,
	0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xff, 0xff, 0x99, 0xf0, 0x00, 0x00, 0x02, 0x04, 0x05, 0x64,
	0x04, 0x02, 0x08, 0x0a, 0x00, 0x03, 0x4c, 0xd5, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x08,
}

func TestPacketLoopbackFamily(t *testing.T) {
	p := gopacket.NewPacket(testPacketLoopbackFamily, LayerTypeLoopback, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeLoopback, LayerTypeIPv4, LayerTypeTCP}, t)
	checkSerialization(p, t)
	if got, ok := p.Layer(LayerTypeLoopback).(*Loopback); ok {
		want := &Loopback{
			BaseLayer: BaseLayer{
				Contents: testPacketLoopbackFamily[:4],
				Payload:  testPacketLoopbackFamily[4:],
			},
			EthType: EthernetTypeUnspec,
			Family:  ProtocolFamilyIPv4,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Loopback packet processing failed:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No Loopback layer type found in packet")
	}
}
