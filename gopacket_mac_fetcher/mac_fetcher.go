// Copyright (c) 2012 Google, Inc. All rights reserved.

// Package gopacket_mac_fetcher is a binary that pulls the list of known MAC
// prefixes from IEEE and writes them out to a go file which is compiled
// into gopacket.  It should be run from the gopacket directory:
//
//  go run gopacket_mac_fetcher/mac_fetcher.go
//  go fmt  # optional
//  go build
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"
)

var url = flag.String("url", "http://standards.ieee.org/develop/regauth/oui/oui.txt", "URL to fetch MACs from")
var filename = flag.String("filename", "valid_mac_prefixes.go", "File to write to")

func main() {
	fmt.Printf("Fetching MACs from %q\n", *url)
	resp, httpErr := http.Get(*url)
	if httpErr != nil {
		panic(httpErr)
	}
	defer resp.Body.Close()
	buffered := bufio.NewReader(resp.Body)
	finder, _ := regexp.Compile("^([0-9A-F]{6})\\s+\\(base 16\\)\\s+(.*)")
	fmt.Printf("Writing to file %q\n", *filename)
	f, fErr := os.Create(*filename)
	if fErr != nil {
		panic(fErr)
	}
	for _, line := range []string{
		"// Copyright (c) 2012 Google, Inc. All rights reserved.",
		"",
		"package gopacket",
		"",
		"// Created by gopacket_mac_fetcher, don't edit manually",
		"// Generated at " + time.Now().String(),
    "// Fetched from " + *url,
		"",
		"// ValidMACPrefixMap maps a valid MAC address prefix to the name of the ",
		"// organization that owns the rights to use it.  We map it to a hidden ",
		"// variable so it won't show up in godoc, since it's a very large map.",
		"var ValidMACPrefixMap map[[3]byte]string = validMACPrefixMap",
		"var validMACPrefixMap map[[3]byte]string = map[[3]byte]string{",
	} {
		f.WriteString(line)
		f.WriteString("\n")
	}
	for line, err := buffered.ReadString('\n'); err == nil; line, err = buffered.ReadString('\n') {
		if matches := finder.FindStringSubmatch(line); matches != nil {
			bytes := make([]byte, 3)
			hex.Decode(bytes, []byte(matches[1]))
			company := matches[2]
			if company == "" {
				company = "PRIVATE"
			}
			f.WriteString(fmt.Sprintf("\t[3]byte{%d, %d, %d}: %q,\n", bytes[0], bytes[1], bytes[2], company))
		}
	}
	f.WriteString("}\n")
	if err := f.Close(); err != nil {
		panic(err)
	}
	fmt.Println("Wrote file successfully")
}
