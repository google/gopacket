// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The pcapdump binary implements a tcpdump-like command line tool with gopacket
// using pcap as a backend data collection mechanism.
package main

import (
	"flag"
	"fmt"
	"github.com/gconnell/gopacket/dumpcommand"
	"github.com/gconnell/gopacket/pcap"
	"log"
	"os"
	"strings"
	"time"
)

var iface = flag.String("i", "eth0", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")

func main() {
	flag.Parse()
	var handle *pcap.Handle
	var err error
	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatalln("PCAP OpenOffline error:", err)
		}
	} else {
		if handle, err = pcap.OpenLive(*iface, *snaplen, true, time.Second); err != nil {
			log.Fatalln("PCAP OpenLive error:", err)
		}
		if len(flag.Args()) > 0 {
			bpffilter := strings.Join(flag.Args(), " ")
			fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
			if err = handle.SetBPFFilter(bpffilter); err != nil {
				log.Fatalln("BPF filter error:", err)
			}
		}
	}
	dumpcommand.Run(handle)
}
