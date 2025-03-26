// Copyright 2013 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package ip6defrag

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
)

func TestFrag(t *testing.T) {
	d := NewIPv6Defragmenter()

	l := &layers.IPv6{
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		NextHeader:   layers.IPProtocolIPv6Fragment,
		HopLimit:     0,
		SrcIP:        net.IPv6zero,
		DstIP:        net.IPv6zero,
	}

	l1 := &layers.IPv6Fragment{
		NextHeader:     layers.IPProtocolIPv6Fragment,
		FragmentOffset: 0,
		MoreFragments:  true,
		Identification: 1,
	}
	l1.Payload = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	l2 := &layers.IPv6Fragment{
		NextHeader:     layers.IPProtocolIPv6Fragment,
		FragmentOffset: 1,
		MoreFragments:  true,
		Identification: 1,
	}
	l2.Payload = []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	l3 := &layers.IPv6Fragment{
		NextHeader:     layers.IPProtocolTCP,
		FragmentOffset: 2,
		MoreFragments:  false,
		Identification: 1,
	}
	l3.Payload = []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}

	ipv6 := d.DefragIPv6(l, l1)
	if ipv6 != nil {
		t.Fatal("input: l1, output shoud be: nil")
	}
	ipv6 = d.DefragIPv6(l, l3)
	if ipv6 != nil {
		t.Fatal("input: l1+l3, output shoud be: nil")
	}
	ipv6 = d.DefragIPv6(l, l2)
	if ipv6 == nil {
		t.Fatal("input: l1+l3+l2, output shoud be: ipv6")
	}
	if ipv6.Payload[0] != 0x01 || ipv6.Payload[15] != 0x18 || ipv6.Payload[16] != 0x21 {
		t.Fatal("return invalid payload")
	}
}
