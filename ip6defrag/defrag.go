// Package ip6defrag implements a IPv6 defragmenter
package main

import (
	"container/list"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"sync"
	"time"
)

//need to check
const (
	IPv6MaximumSize            = 65535
	IPv6MaximumFragmentOffset  = 8191
	IPv6MaximumFragmentListLen = 8191
)

type fragmentList struct {
	List          list.List
	Highest       uint16
	Current       uint16
	FinalReceived bool
	LastSeen      time.Time
}

var debug debugging = false // or flip to false
type debugging bool

func (d debugging) Printf(format string, args ...interface{}) {
	if d {
		log.Printf(format, args...)
	}
}

type IPv6Defragmenter struct {
	sync.RWMutex
	ipFlows map[ipv6]*fragmentList
}

type ipv6 struct {
	ip6 gopacket.Flow
	id  uint32
}

// newIPv6 returns a new initialized IPv6 Flow
func newIpv6(packet gopacket.Packet) ipv6 {
	frag := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
	ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	return ipv6{
		ip6: ip.NetworkFlow(),
		id:  frag.Identification,
	}
}

func (d *IPv6Defragmenter) DefragIPv6(in gopacket.Packet) (gopacket.Packet, error) {
	// check if we need to defrag
	frag := in.Layer(layers.LayerTypeIPv6Fragment)
	if frag == nil {
		return in, nil
	}
	v6frag := frag.(*layers.IPv6Fragment)
	st, err := d.securityChecks(v6frag)
	if err != nil || st == false {
		return nil, err
	}
	// ok, got a fragment
	debug.Printf("defrag: got in.Id=%d in.FragOffset=%d",
		v6frag.Identification, v6frag.FragmentOffset*8)

	// do we already has seen a flow between src/dst with that Id
	ipf := newIpv6(in)
	var fl *fragmentList
	var exist bool
	d.Lock()
	fl, exist = d.ipFlows[ipf]
	if !exist {
		debug.Printf("defrag: creating a new flow\n")
		fl = new(fragmentList)
		d.ipFlows[ipf] = fl
	}
	d.Unlock()
	// insert, and if final build it
	out, err2 := fl.insert(in)

	// at last, if we hit the maximum frag list len
	// without any defrag success, we just drop everything and
	// raise an error
	if out == nil && fl.List.Len()+1 > IPv6MaximumFragmentListLen {
		d.Lock()
		fl = new(fragmentList)
		d.ipFlows[ipf] = fl
		d.Unlock()
		return nil, fmt.Errorf("defrag: Fragment List hits its maximum"+
			"size(%d), without sucess. Flushing the list",
			IPv6MaximumFragmentListLen)
	}

	// if we got a packet, it's a new one, and he is defragmented
	if out != nil {
		return out, nil
	}
	return nil, err2
}

func (d *IPv6Defragmenter) securityChecks(in *layers.IPv6Fragment) (bool, error) {
	if in.FragmentOffset > IPv6MaximumFragmentOffset {
		return false, fmt.Errorf("defrag: fragment offset too big "+
			"(handcrafted? %d > %d)", in.FragmentOffset, IPv6MaximumFragmentOffset)
	}
	fragOffset := in.FragmentOffset * 8
	if fragOffset+uint16(len(in.Payload)) > IPv6MaximumSize {
		return false, fmt.Errorf("defrag: fragment will overrun "+
			"(handcrafted? %d > %d)", fragOffset+uint16(len(in.Payload)), IPv6MaximumFragmentOffset)
	}
	return true, nil
}

func (f *fragmentList) insert(in gopacket.Packet) (gopacket.Packet, error) {
	fragv6 := in.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
	fragOffset := fragv6.FragmentOffset * 8
	if fragOffset >= f.Highest {
		f.List.PushBack(in)
	} else {
		for e := f.List.Front(); e != nil; e = e.Next() {
			packet, _ := e.Value.(gopacket.Packet)
			frag := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
			if fragv6.FragmentOffset <= frag.FragmentOffset {
				debug.Printf("defrag: inserting frag %d before existing frag %d \n",
					fragOffset, frag.FragmentOffset*8)
				f.List.InsertBefore(in, e)
				break
			}
		}
	}
	f.LastSeen = in.Metadata().Timestamp
	fragLength := in.Layer(layers.LayerTypeIPv6).(*layers.IPv6).Length - 8 // need to conform
	// After inserting the Fragment, we update the counters
	if f.Highest < fragOffset+fragLength {
		f.Highest = fragOffset + fragLength
	}

	f.Current = f.Current + fragLength

	debug.Printf("defrag: insert ListLen: %d Highest:%d Current:%d\n",
		f.List.Len(),
		f.Highest, f.Current)

	// Final Fragment ?
	if fragv6.MoreFragments == false {
		f.FinalReceived = true
	}
	// Ready to try defrag ?
	if f.FinalReceived && f.Highest == f.Current {
		return f.build(in)
	}
	return nil, nil
}

//need work
func (f *fragmentList) build(in gopacket.Packet) (gopacket.Packet, error) {
	var final []byte
	var currentOffset uint16 = 0

	debug.Printf("defrag: building the datagram \n")
	for e := f.List.Front(); e != nil; e = e.Next() {
		pack, _ := e.Value.(gopacket.Packet)
		frag := pack.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
		ip := pack.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if frag.FragmentOffset*8 == currentOffset {
			debug.Printf("defrag: building - adding %d\n", frag.FragmentOffset*8)
			final = append(final, frag.Payload...)
			currentOffset = currentOffset + ip.Length - 8
		} else if frag.FragmentOffset*8 < currentOffset {
			// overlapping fragment - let's take only what we need
			startAt := currentOffset - frag.FragmentOffset*8
			debug.Printf("defrag: building - overlapping, starting at %d\n",
				startAt)
			if startAt > ip.Length-8 {
				return nil, fmt.Errorf("defrag: building - invalid fragment")
			}
			final = append(final, frag.Payload[startAt:]...)
			currentOffset = currentOffset + frag.FragmentOffset*8
		} else {
			// Houston - we have an hole !
			debug.Printf("defrag: hole found while building, " +
				"stopping the defrag process\n")
			return nil, fmt.Errorf("defrag: building - hole found")
		}
		debug.Printf("defrag: building - next is %d\n", currentOffset)
	}
	final_ipv6 := in.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	final_frag := in.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
	// TODO recompute IP Checksum
	out := &layers.IPv6{
		Version:      final_ipv6.Version,
		TrafficClass: final_ipv6.TrafficClass,
		FlowLabel:    final_ipv6.FlowLabel,
		Length:       f.Highest,
		NextHeader:   final_frag.NextHeader,
		HopLimit:     final_ipv6.HopLimit,
		SrcIP:        final_ipv6.SrcIP,
		DstIP:        final_ipv6.DstIP,
		HopByHop:     final_ipv6.HopByHop,
	}
	out.Payload = final
	v6SerializeBuffer := gopacket.NewSerializeBuffer()
	v6Buffer, _ := v6SerializeBuffer.PrependBytes(len(final))
	copy(v6Buffer, final)
	ops := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	out.SerializeTo(v6SerializeBuffer, ops)
	outPacket := gopacket.NewPacket(v6SerializeBuffer.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
	outPacket.Metadata().CaptureLength = len(outPacket.Data())
	outPacket.Metadata().Length = len(outPacket.Data())
	return outPacket, nil
}

func NewIPv6Defragmenter() *IPv6Defragmenter {
	return &IPv6Defragmenter{
		ipFlows: make(map[ipv6]*fragmentList),
	}
}
