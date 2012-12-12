// Copyright 2012 Google, Inc. All rights reserved.

// +build ignore

// This benchmark reads in file <tempdir>/gopacket_benchmark.pcap and measures
// the time it takes to decode all packets from that file.  If the file doesn't
// exist, it's pulled down from a publicly available location.  However, you can
// feel free to substitute your own file at that location, in which case the
// benchmark will run on your own data.
// It's also useful for figuring out which packets may be causing errors.  Pass
// in the --printErrors flag, and it'll print out error layers for each packet
// that has them.
package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"github.com/gconnell/gopacket/pcap"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

var decodeLazy *bool = flag.Bool("lazy", false, "If true, use lazy decoding")
var decodeNoCopy *bool = flag.Bool("nocopy", false, "If true, avoid an extra copy when decoding packets")
var printErrors *bool = flag.Bool("printErrors", false, "If true, check for and print error layers.")
var repeat *int = flag.Int("repeat", 1, "Read over the file N times")

func main() {
	flag.Parse()
	filename := os.TempDir() + string(os.PathSeparator) + "gopacket_benchmark.pcap"
	if _, err := os.Stat(filename); err != nil {
		// This URL points to a publicly available packet data set from a DARPA
		// intrusion detection evaluation.  See
		// http://www.ll.mit.edu/mission/communications/cyber/CSTcorpora/ideval/data/1999/training/week1/index.html
		// for more details.
		url := "http://www.ll.mit.edu/mission/communications/cyber/CSTcorpora/ideval/data/1999/training/week1/tuesday/inside.tcpdump.gz"
		fmt.Println("Local pcap file", filename, "doesn't exist, reading from", url)
		if resp, err := http.Get(url); err != nil {
			panic(err)
		} else if out, err := os.Create(filename); err != nil {
			panic(err)
		} else if gz, err := gzip.NewReader(resp.Body); err != nil {
			panic(err)
		} else if n, err := io.Copy(out, gz); err != nil {
			panic(err)
		} else if err := gz.Close(); err != nil {
			panic(err)
		} else if err := out.Close(); err != nil {
			panic(err)
		} else {
			fmt.Println("Successfully read", n, "bytes from url, unzipped to local storage")
		}
	}
	fmt.Println("Reading file once through to hopefully cache most of it")
	if f, err := os.Open(filename); err != nil {
		panic(err)
	} else if n, err := io.Copy(ioutil.Discard, f); err != nil {
		panic(err)
	} else if err := f.Close(); err != nil {
		panic(err)
	} else {
		fmt.Println("Read in file", filename, ", total of", n, "bytes")
	}
	for i := 0; i < *repeat; i++ {
		fmt.Println("Opening file", filename, "for read")
		if h, err := pcap.OpenOffline(filename); err != nil {
			panic(err)
		} else {
			h.DecodeOptions.Lazy = *decodeLazy
			h.DecodeOptions.NoCopy = *decodeNoCopy
			count, errors := 0, 0
			start := time.Now()
			for packet, err := h.Next(); err != pcap.NextErrorNoMorePackets; packet, err = h.Next() {
				if err != nil {
					fmt.Println("Error reading in packet:", err)
				}
				count++
				if *printErrors && packet.ErrorLayer() != nil {
					fmt.Println("Error decoding packet:", packet.ErrorLayer().Error())
					errors++
				}
			}
			duration := time.Since(start)
			fmt.Printf("Read in %v packets in %v, %v per packet\n", count, duration, duration/time.Duration(count))
			if *printErrors {
				fmt.Printf("%v errors, successfully decoded %.02f%%\n", errors, float64(count-errors)*100.0/float64(count))
			}
		}
	}
}
