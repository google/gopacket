// Copyright 2013 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Package ip6defrag implements a IPv6 defragmenter
package ip6defrag

import (
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

// IPv6Defragmenter is a struct which embedded a map of all fragment/packet.
type IPv6Defragmenter struct {
	container map[uint32]*fragment
	lock      *sync.Mutex
}

// fragment is a IPv6 fragment list struct.
type fragment struct {
	ipv6       *layers.IPv6
	offset     uint16
	payload    []byte
	more       bool
	nextheader layers.IPProtocol
	next       *fragment
	time       time.Time
}

// NewIPv6Defragmenter returns a new IPv6Defragmenter with an initialized map.
func NewIPv6Defragmenter() *IPv6Defragmenter {
	return &IPv6Defragmenter{
		container: make(map[uint32]*fragment),
		lock:      &sync.Mutex{},
	}
}

// DefragIPv6 takes in an IPv6 packet with a fragment payload.
//
// It do not modify the IPv6 layer fragment in place,
// It returns a ready-to be used IPv6 layer.
//
// If and we don't have all fragments,
// it will return nil and store whatever internal
// information it needs to eventually defrag the packet.
//
// If the IPv6 fragment is the last fragment needed to reconstruct
// the packet, a new IPv6 layer will be returned, and will be set to
// the entire defragmented packet,
//
// It use a map of all the running flows
//
// Usage example:
//
// var d = NewIPv6Defragmenter()
// func HandlePacket(p gopacket.Packet) {
// 	ipv6, ok := p.NetworkLayer().(*layers.IPv6)
// 	if !ok {
// 		// ignore: not ipv6
// 		return
// 	}
// 	if fg, ok := p.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment); ok {
// 		if fg.NextHeader != layers.IPProtocolUDP && fg.NextHeader != layers.IPProtocolTCP {
// 			// ignore: !TCP and !UDP fragment
// 			return
// 		}
// 		ipv6 = d.DefragIPv6(ipv6, fg)
// 		if ipv6 == nil {
// 			// ignore: do nothing, wait next fragment
// 			return
// 		}
// 	}
// 	// You got the ipv6 layer
// }
func (d *IPv6Defragmenter) DefragIPv6(ipv6 *layers.IPv6, fg *layers.IPv6Fragment) *layers.IPv6 {
	d.lock.Lock()
	defer func() {
		d.container[fg.Identification].time = time.Now()
		d.lock.Unlock()
	}()
	in := &fragment{
		offset:     fg.FragmentOffset,
		payload:    fg.LayerPayload(),
		more:       fg.MoreFragments,
		nextheader: fg.NextHeader,
	}
	// first
	if in.offset == 0 {
		in.ipv6 = ipv6
	}
	f, ok := d.container[fg.Identification]
	if !ok {
		// remeber the first coming
		d.container[fg.Identification] = in
		return nil
	}

	// insert into list and make the id map to the first one
	var prev *fragment
	for {
		if in.offset == f.offset {
			break
		}
		if in.offset < f.offset {
			if prev == nil {
				d.container[fg.Identification] = in
				in.next = f
				break
			}
			if prev != nil {
				prev.next = in
				in.next = f
				break
			}
		}
		if f.next == nil {
			f.next = in
			break
		}
		prev = f
		f = f.next
	}

	f = d.container[fg.Identification]
	// first one is not the first, return and continue
	if f.offset != 0 {
		return nil
	}
	ok = false
	for {
		if !f.more {
			// no more
			ok = true
			break
		}
		// need more, but no next one or next one is not the next
		if f.next == nil || f.offset+uint16(len(f.payload)/8) != f.next.offset {
			break
		}
		// continue
		f = f.next
	}
	if !ok {
		return nil
	}

	// make the payload
	f = d.container[fg.Identification]
	var b []byte
	for {
		b = append(b, f.payload...)
		if !f.more {
			break
		}
		f = f.next
	}
	nh := f.nextheader

	f = d.container[fg.Identification]
	l := &layers.IPv6{
		Version:      6,
		TrafficClass: f.ipv6.TrafficClass,
		FlowLabel:    f.ipv6.FlowLabel,
		NextHeader:   nh,
		HopLimit:     f.ipv6.HopLimit,
		SrcIP:        f.ipv6.SrcIP,
		DstIP:        f.ipv6.DstIP,
	}
	l.Payload = b
	return l
}

// DiscardOlderThan forgets all packets without any activity since
// time t. It returns the number of FragmentList aka number of
// fragment packets it has discarded.
func (d *IPv6Defragmenter) DiscardOlderThan(t time.Time) int {
	var n int
	d.lock.Lock()
	defer d.lock.Unlock()
	for k, v := range d.container {
		if v.time.Before(t) {
			n = n + 1
			delete(d.container, k)
		}
	}
	return n
}
