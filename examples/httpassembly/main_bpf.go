// +build darwin dragonfly freebsd linux netbsd openbsd solaris

// from
//  /home/rs/go/src/github.com/google/gopacket/examples/httpassembly/main.go

// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This binary provides sample code for using the gopacket TCP assembler and TCP
// stream reader.  It reads packets off the wire and reconstructs HTTP requests
// it sees, logging them.
package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"net/http"
	"syscall"
	"time"

	"github.com/google/gopacket"
	//"github.com/hb9cwp/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	//"github.com/google/gopacket/pcap"
	//"github.com/google/gopacket/bsdbpf"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/hb9cwp/gopacket/bsdbpf"
)

var iface = flag.String("i", "alc0", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")

//var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
//var filter = flag.String("f", "tcp and dst port 80", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

/*
var bpfARPFilterProg = []syscall.BpfInsn{
	// make sure this is an arp packet
	*syscall.BpfStmt(syscall.BPF_LD+syscall.BPF_H+syscall.BPF_ABS, 12),
	*syscall.BpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, 0x0806, 0, 1),
	// if we passed all the tests, ask for the whole packet.
	*syscall.BpfStmt(syscall.BPF_RET+syscall.BPF_K, -1),
	// otherwise, drop it.
	*syscall.BpfStmt(syscall.BPF_RET+syscall.BPF_K, 0),
}
*/

/*  BPF filter expressions for TCP from OpenBSD man bpf() page (at the very bottom of the man page)
 http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man4/bpf.4?query=bpf

...
Finally, this filter returns only TCP finger packets. We must parse the IP header to reach the TCP header. The
BPF_JSET instruction checks that the IP fragment offset is 0 so we are sure that we have a TCP header.

struct bpf_insn insns[] = {
 BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
 BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 10),
 BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
 BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP, 0, 8),
 BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 20),
 BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 0x1fff, 6, 0),
 BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 14),
 BPF_STMT(BPF_LD+BPF_H+BPF_IND, 14),
 BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 79, 2, 0),
 BPF_STMT(BPF_LD+BPF_H+BPF_IND, 16),
 BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 79, 0, 1),
 BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
 BPF_STMT(BPF_RET+BPF_K, 0),
}
*/

// tcp and dst port 80
var bpfHTTPFilterProg = []syscall.BpfInsn{
	// if EtherType is IPv4 (at offset (2*6), with VLAN tag (2*6+4))
	*syscall.BpfStmt(syscall.BPF_LD+syscall.BPF_H+syscall.BPF_ABS, 12),
	*syscall.BpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, 0x0800, 2, 0),
	// if EtherType is IPv6 (= 0x86DD)
	*syscall.BpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, 0x86DD, 8, 0),
	// drop it.
	*syscall.BpfStmt(syscall.BPF_RET+syscall.BPF_K, 0),

	// if IPProto is TCP over IPv4
	*syscall.BpfStmt(syscall.BPF_LD+syscall.BPF_B+syscall.BPF_ABS, (14 + 9)),
	*syscall.BpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, 6, 1, 0),
	// drop it.
	*syscall.BpfStmt(syscall.BPF_RET+syscall.BPF_K, 0),
	// if dst port is 80
	*syscall.BpfStmt(syscall.BPF_LD+syscall.BPF_H+syscall.BPF_ABS, (14 + 20 + 2)),
	*syscall.BpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, 80, 1, 0),
	// drop it.
	*syscall.BpfStmt(syscall.BPF_RET+syscall.BPF_K, 0),
	// return the whole packet.
	*syscall.BpfStmt(syscall.BPF_RET+syscall.BPF_K, -1),

	// if IPProto is TCP over IPv6
	*syscall.BpfStmt(syscall.BPF_LD+syscall.BPF_B+syscall.BPF_ABS, (14 + 6)),
	*syscall.BpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, 6, 1, 0),
	// drop it.
	*syscall.BpfStmt(syscall.BPF_RET+syscall.BPF_K, 0),
	// if dst port is 80
	*syscall.BpfStmt(syscall.BPF_LD+syscall.BPF_H+syscall.BPF_ABS, (14 + 40 + 2)),
	*syscall.BpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, 80, 1, 0),
	// drop it.
	*syscall.BpfStmt(syscall.BPF_RET+syscall.BPF_K, 0),
	// return the whole packet.
	*syscall.BpfStmt(syscall.BPF_RET+syscall.BPF_K, -1),
}

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			//log.Println("Received request from stream", h.net, h.transport, ":", req, "with", bodyBytes, "bytes in request body")
			log.Println(h.net, h.transport, req.Method, req.Proto, req.Host, req.URL, bodyBytes)
		}
	}
}

func main() {
	defer util.Run()()
	//var handle *pcap.Handle
	var handle *bsdbpf.BPFSniffer
	var err error
	var options = bsdbpf.Options{
		BPFDeviceName: "",
		//ReadBufLen:       32767,
		ReadBufLen: 0, // asks BPF for buffer size (32768 with OpenBSD 5.7)
		//Timeout:          nil,
		Timeout: &syscall.Timeval{Sec: 1, Usec: 0},
		Promisc: true,
		//Immediate:      true,
		Immediate:        false,
		PreserveLinkAddr: true,
	}

	// Set up pcap packet capture
	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		//handle, err = pcap.OpenOffline(*fname)
		log.Fatal("Reading from pcap dump %q not yet implemented on BSD", *fname)
	} else {
		log.Printf("Starting capture on interface %q", *iface)
		//handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
		//handle, err = bsdbpf.NewBPFSniffer(*iface, nil)
		handle, err = bsdbpf.NewBPFSniffer(*iface, &options)
	}
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBpfReadFilterProgram(bpfHTTPFilterProg); err != nil {
		log.Fatal(err)
	}
	if err := handle.FlushBpf(); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	//packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)

	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if *logAllPackets {
				log.Println(packet)
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
