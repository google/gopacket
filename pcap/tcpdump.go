// Copyright 2012 Google, Inc. All rights reserved.

// +build ignore

// This tool is a simple tcpdump built on gopacket, mostly to test
// packet->string conversions.
package main

import (
	"flag"
	"fmt"
	"github.com/gconnell/gopacket"
	"github.com/gconnell/gopacket/pcap"
	"os"
	"strings"
	"time"
)

var iface = flag.String("i", "eth0", "Interface to read from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "Snap length")

func main() {
	flag.Parse()
	var handle *pcap.Handle
	var err error
	if *fname == "" {
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, time.Second)
	} else {
		handle, err = pcap.OpenOffline(*fname)
	}
	if err != nil {
		panic(err)
	}
	filter := strings.Join(flag.Args(), " ")
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			panic(err)
		}
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.NoCopy = true
	fmt.Fprintln(os.Stderr, "Starting to read packets")
	i := 0
	for packet := range source.Packets() {
		fmt.Println("Packet", i)
		i++
		fmt.Println(packet)
		os.Stdout.Sync()
	}
}
