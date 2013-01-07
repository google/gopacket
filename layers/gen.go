// Copyright 2012 Google, Inc. All rights reserved.

// +build ignore

// This binary pulls known ports from IANA, and uses them to populate
// iana_ports.go's TCPPortNames and UDPPortNames maps.
//
//  go run gen.go | gofmt > iana_ports.go
package main

import (
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

const fmtString = `// Copyright 2012 Google, Inc. All rights reserved.

package layers

// Created by gen.go, don't edit manually
// Generated at %s
// Fetched from %q

var TCPPortNames = tcpPortNames
var UDPPortNames = udpPortNames
var tcpPortNames = map[TCPPort]string{
%s}
var udpPortNames = map[UDPPort]string{
%s}
`

var url = flag.String("url", "http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml", "URL to grab port numbers from")

func main() {
	fmt.Fprintf(os.Stderr, "Fetching ports from %q\n", *url)
	resp, err := http.Get(*url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, "Parsing XML")
	var registry struct {
		Records []struct {
			Protocol string `xml:"protocol"`
			Number   int    `xml:"number"`
			Name     string `xml:"name"`
		} `xml:"record"`
	}
	xml.Unmarshal(body, &registry)
	var tcpPorts bytes.Buffer
	var udpPorts bytes.Buffer
	done := map[string]map[int]bool{
		"tcp": map[int]bool{},
		"udp": map[int]bool{},
	}
	for _, r := range registry.Records {
		if r.Name == "" {
			continue
		}
		var b *bytes.Buffer
		switch r.Protocol {
		case "tcp":
			b = &tcpPorts
		case "udp":
			b = &udpPorts
		default:
			continue
		}
		if done[r.Protocol][r.Number] {
			continue
		}
		done[r.Protocol][r.Number] = true
		fmt.Fprintf(b, "\t%d: %q,\n", r.Number, r.Name)
	}
	fmt.Fprintln(os.Stderr, "Writing results to stdout")
	fmt.Printf(fmtString, time.Now(), *url, tcpPorts.String(), udpPorts.String())
}
