// Copyright 2012 Google, Inc. All rights reserved.

package pcap

import (
	"github.com/gconnell/gopacket"
	"github.com/gconnell/gopacket/layers"
	"testing"
)

func TestPcapFileRead(t *testing.T) {
	packets := []gopacket.Packet{}
	if handle, err := OpenOffline("test.pcap"); err != nil {
		t.Fatal(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			packets = append(packets, packet)
		}
	}
	if len(packets) != 24 {
		t.Fatal("Incorrect number of packets, want 24 got", len(packets))
	}
	for i, p := range packets {
		if p.Layer(layers.LayerTypeTCP) == nil {
			t.Error("Packet", i, "is not a TCP packet:\n", p)
		}
	}
}
