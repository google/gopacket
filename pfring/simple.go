// Copyright 2012 Google, Inc. All rights reserved.

// +build ignore

// simple is a very simple example of how to use PFRing to capture and decode
// packets with gopacket.
package main

import (
	"flag"
	"fmt"
	"github.com/gconnell/gopacket"
	"github.com/gconnell/gopacket/layers"
	"github.com/gconnell/gopacket/pfring"
	"io"
)

var filter *string = flag.String("filter", "", "BPF filter")
var device *string = flag.String("device", "eth0", "Device to read packets from")

func main() {
	fmt.Println("Starting...")
	flag.Parse()
	ring, err := pfring.NewRing(*device, 65536, pfring.FlagPromisc)
	if err != nil {
		panic(err)
	}
	if *filter != "" {
		fmt.Println("Setting BPF filter:", *filter)
		if err := ring.SetBPFFilter(*filter); err != nil {
			panic(err)
		}
	}
	ring.Enable() // Must do this!, or you get no packets!
	packetSource := gopacket.NewPacketSource(ring, layers.LinkTypeEthernet)
	fmt.Println("Waiting for packets...")
	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println("ERROR:", err)
			continue
		}
		fmt.Println("Read packet:")
		for _, l := range packet.Layers() {
			fmt.Println("\t", l.LayerType())
		}
	}
}
