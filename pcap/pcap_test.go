// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcap

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"testing"
)

func TestPcapFileRead(t *testing.T) {
	for _, file := range []struct {
		filename       string
		num            int
		expectedLayers []gopacket.LayerType
	}{
		{"test_loopback.pcap",
			24,
			[]gopacket.LayerType{
				layers.LayerTypeLoopback,
				layers.LayerTypeIPv6,
				layers.LayerTypeTCP,
			},
		},
		{"test_ethernet.pcap",
			16,
			[]gopacket.LayerType{
				layers.LayerTypeEthernet,
				layers.LayerTypeIPv4,
				layers.LayerTypeTCP,
			},
		},
	} {
		t.Log("Processing file", file.filename)

		packets := []gopacket.Packet{}
		if handle, err := OpenOffline(file.filename); err != nil {
			t.Fatal(err)
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				packets = append(packets, packet)
			}
		}
		if len(packets) != file.num {
			t.Fatal("Incorrect number of packets, want", file.num, "got", len(packets))
		}
		for i, p := range packets {
			t.Log("Packet ", i, "\n", p.Dump())
			for _, layertype := range file.expectedLayers {
				if p.Layer(layertype) == nil {
					t.Error("Packet", i, "has no layer type", layertype)
				}
			}
		}
	}
}
