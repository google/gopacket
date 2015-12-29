// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The pcaplay binary load an offline capture (pcap file) and replay
// it on the select interface, with an emphasis on packet timing
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/pcap"
)

var iface = flag.String("i", "eth0", "Interface to write packets to")
var fname = flag.String("r", "", "Filename to read from")

var lastTS time.Time
var lastSend time.Time

func writePacket(handle *pcap.Handle, buf []byte, ci gopacket.CaptureInfo) {
	if ci.CaptureLength != ci.Length {
		// do not write truncated packets
		return
	}

	intervalInCapture := ci.Timestamp.Sub(lastTS)
	elapsedTime := time.Now().Sub(lastSend)

	if (intervalInCapture > elapsedTime) && !lastSend.IsZero() {
		time.Sleep(intervalInCapture - elapsedTime)
	}

	lastSend = time.Now()
	if err := handle.WritePacketData(buf); err != nil {
		log.Fatal(err)
	}
	lastTS = ci.Timestamp
}

func main() {
	defer util.Run()()

	// Sanity checks
	if *fname == "" {
		log.Fatal("Need a input file")
	}

	// Open PCAP file + handle potential BPF Filter
	handleRead, err := pcap.OpenOffline(*fname)
	if err != nil {
		log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
	}
	defer handleRead.Close()
	if len(flag.Args()) > 0 {
		bpffilter := strings.Join(flag.Args(), " ")
		fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
		if err = handleRead.SetBPFFilter(bpffilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}
	// Open up a second pcap handle for packet writes.
	handleWrite, err := pcap.OpenLive(*iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("PCAP OpenLive error (handle to write packet):", err)
	}
	defer handleWrite.Close()

	// Loop over packets and write them
	for {
		data, ci, err := handleRead.ReadPacketData()
		switch {
		case err == io.EOF:
			return
		case err != nil:
			log.Fatal(err)
		default:
			writePacket(handleWrite, data, ci)
		}
	}

}
