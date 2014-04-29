// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// +build ignore

// This binary tests that PCAP packet capture is working correctly by issuing
// HTTP requests, then making sure we actually capture data off the wire.
package main

import (
	"code.google.com/p/gopacket/pcap"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

var mode = flag.String("mode", "basic", "One of: basic,filtered,timestamp")

func main() {
	flag.Parse()
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		// Generate traffic to look for.
		for _ = range time.Tick(time.Second) {
			go func() {
				if resp, err := http.Get("http://code.google.com"); err != nil {
					log.Printf("Could not get HTTP: %v", err)
				} else {
					resp.Body.Close()
				}
			}()
		}
	}()
	for _, iface := range ifaces {
		log.Printf("Trying capture on %q", iface.Name)
		if err := tryCapture(iface); err != nil {
			log.Printf("Error capturing on %q: %v", iface.Name, err)
		} else {
			log.Printf("Successfully captured on %q", iface.Name)
			return
		}
	}
	os.Exit(1)
}

func tryCapture(iface net.Interface) error {
	if iface.Name[:2] == "lo" {
		return fmt.Errorf("skipping loopback")
	}
	h, err := pcap.OpenLive(iface.Name, 65536, false, time.Second*3)
	if err != nil {
		return fmt.Errorf("openlive: %v", err)
	}
	defer h.Close()
	switch *mode {
	case "basic":
	case "filtered":
		if err := h.SetBPFFilter("port 80 or port 443"); err != nil {
			return fmt.Errorf("setbpf: %v", err)
		}
	case "timestamp":
		sources := h.SupportedTimestamps()
		if len(sources) == 0 {
			return fmt.Errorf("no supported timestamp sources")
		}
		if err := h.SetTimestampSource(sources[0]); err != nil {
			return fmt.Errorf("settimestampsource(%v): %v", sources[0], err)
		}
	default:
		panic("Invalid --mode: " + *mode)
	}
	h.ReadPacketData() // Do one dummy read to clear any timeouts.
	data, ci, err := h.ReadPacketData()
	if err != nil {
		return fmt.Errorf("readpacketdata: %v", err)
	}
	log.Printf("Read packet, %v bytes, CI: %+v", len(data), ci)
	return nil
}
