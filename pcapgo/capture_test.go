// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
//go:build linux && go1.13
// +build linux,go1.13

package pcapgo_test

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	timeout = 100 * time.Millisecond
)

func Example_captureEthernet() {
	f, err := os.Create(filepath.Join(os.TempDir(), "lo.pcap"))
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("WriteFileHeader: %v", err)
	}

	handle, err := pcapgo.NewEthernetHandle("lo")
	if err != nil {
		log.Fatalf("OpenEthernet: %v", err)
	}

	pkgsrc := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for packet := range pkgsrc.PacketsCtx(context.Background()) {
		if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			log.Fatalf("pcap.WritePacket(): %v", err)
		}
	}
}

func TestEthernetHandle_Close_WithTimeout(t *testing.T) {
	var (
		handle *pcapgo.EthernetHandle
		err    error
		done   = make(chan struct{})
	)

	handle, err = pcapgo.NewEthernetHandle(setupDummyInterface(t))
	if err != nil {
		t.Fatalf("OpenEthernet: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	pkgsrc := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)

	go consumePacketSource(ctx, t, pkgsrc, done)

	select {
	case _, more := <-done:
		if more {
			t.Fatalf("done channel is polluted?!")
		} else {
			t.Log("PacketSource got closed")
		}
	case <-time.After(2 * timeout):
	}
}

func TestEthernetHandle_Close_WithCancel(t *testing.T) {
	var (
		handle *pcapgo.EthernetHandle
		err    error
		done   = make(chan struct{})
	)

	handle, err = pcapgo.NewEthernetHandle(setupDummyInterface(t))
	if err != nil {
		t.Fatalf("OpenEthernet: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	pkgsrc := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	go consumePacketSource(ctx, t, pkgsrc, done)

	go func() {
		<-time.After(timeout)
		cancel()
	}()

	select {
	case _, more := <-done:
		if more {
			t.Fatalf("done channel is polluted?!")
		} else {
			t.Log("PacketSource got closed")
		}
	case <-time.After(2 * timeout):
	}
}

func consumePacketSource(ctx context.Context, tb testing.TB, pkgsrc *gopacket.PacketSource, done chan<- struct{}) {
	tb.Helper()
	var writer = pcapgo.NewWriter(new(bytes.Buffer))
	defer close(done)
	for packet := range pkgsrc.PacketsCtx(ctx) {
		if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			tb.Errorf("pcap.WritePacket(): %v", err)
		}
	}
}

var (
	dummyInterfaceIdx int32 = -1
)

// setupDummyInterface configures a dummy interface and returns the generated interface name.
// It assigns an address from the 127.10.0.0/24 network.
// It does not check if there are already more than 254 interfaces.
// If there are the call to netlink.ParseAddr will fail because 127.10.0.256/24 isn't a valid IP address,
// but it should be fine for testing purposes.
func setupDummyInterface(tb testing.TB) (ifName string) {
	tb.Helper()
	la := netlink.NewLinkAttrs()
	idx := atomic.AddInt32(&dummyInterfaceIdx, 1)
	la.Name = fmt.Sprintf("dummy%02d", idx)
	dummyInterface := &netlink.Dummy{LinkAttrs: la}
	if err := netlink.LinkAdd(dummyInterface); err != nil {
		tb.Fatalf("netlink.LinkAdd() error = %v", err)
	}

	var (
		link netlink.Link
		addr *netlink.Addr
		err  error
	)

	link, err = netlink.LinkByName(la.Name)
	if err != nil {
		tb.Fatalf("netlink.LinkByName() error = %v", err)
	}

	tb.Cleanup(func() {
		if err := netlink.LinkDel(link); err != nil {
			tb.Fatalf("netlink.LinkDel() error = %v", err)
		}
	})

	addr, err = netlink.ParseAddr(fmt.Sprintf("127.10.0.%d/24", idx+1))
	if err != nil {
		tb.Fatalf("netlink.ParseAddr() = %v", err)
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		tb.Fatalf("netlink.AddrAdd() error = %v", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		tb.Fatalf("netlink.LinkSetUp() error = %v", err)
	}

	return la.Name
}
