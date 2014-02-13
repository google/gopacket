// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The pcapdump binary implements a tcpdump-like command line tool with gopacket
// using pcap as a backend data collection mechanism.
package main

import (
	"code.google.com/p/gopacket/dumpcommand"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

var iface = flag.String("i", "eth0", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var tstype = flag.String("timestamp_type", "", "Type of timestamps to use")

func main() {
	flag.Parse()
	var handle *pcap.Handle
	var err error
	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatalln("PCAP OpenOffline error:", err)
		}
	} else {
		if handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, time.Second); err != nil {
			log.Fatalln("PCAP OpenLive error:", err)
		}
		if *tstype != "" {
			if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
				log.Fatalf("Supported timestamp types: %v", handle.SupportedTimestamps())
			} else if err := handle.SetTimestampSource(t); err != nil {
				log.Fatalf("Supported timestamp types: %v", handle.SupportedTimestamps())
			}
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
