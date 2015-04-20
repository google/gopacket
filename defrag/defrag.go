package defrag

import (
	"container/list"
	"fmt"
	"log"
	"sync"
	"time"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
)

// Quick and Easy yo use debug code to trace
// how defrag works.
var debug debugging = false // or flip to false
type debugging bool

func (d debugging) Printf(format string, args ...interface{}) {
	if d {
		log.Printf(format, args...)
	}
}

type Defragmenter interface {
	// DefragIPv4 takes in an IPv4 packet with a fragment payload.
	//
	// It modifies the IPv4 layer in place, returning true if the
	// modified layer is now a full IPv4 payload.
	//
	// If the passed-in IP layer is NOT fragmented, it will
	// immediately return true without modifying the layer.
	//
	// If the IPv4 layer is a fragment and we don't have all
	// fragments, it will return false and store whatever internal
	// information it needs to eventually defrag the packet.
	//
	// If the IPv4 layer is the last fragment needed to reconstruct
	// the packet, *ip will be set to the entire defragmented packet,
	// and the function will return true.
	DefragIPv4(IPv4 *layers.IPv4) (bool, error)

	// DiscardOlderThan discards all packets we haven't seen a
	// fragment for since 't'.
	// It returns the number of packets discarded in this way.
	DiscardOlderThan(t time.Time) int
}

const (
	IPv4MinimumFragmentSize    = 576
	IPv4MaximumSize            = 65535
	IPv4MaximumFragmentOffset  = 8189
	IPv4MaximumFragmentListLen = 8
)

// DefragIPv4 implements the DefragIPv4 interface.
// It use a map of all the running flows
func (d *IPv4Defragmenter) DefragIPv4(ip *layers.IPv4) (bool, error) {
	// check if we need to defrag
	if st := d.DontDefrag(ip); st == true {
		return true, nil
	}
	// perfom security checks
	st, err := d.SecurityChecks(ip)
	if err != nil || st == false {
		return st, err
	}

	// ok, got a fragment
	debug.Printf("defrag: got ip.Id=%d ip.FragOffset=%d ip.Flags=%d\n",
		ip.Id, ip.FragOffset*8, ip.Flags)

	// do we already has seen a flow between src/dst with that Id
	ipf := *NewIPv4Flow(ip)
	var fl *FragmentList
	var exist bool
	d.Lock()
	fl, exist = d.IPFlows[ipf]
	if !exist {
		debug.Printf("defrag: creating a new flow\n")
		fl = new(FragmentList)
		d.IPFlows[ipf] = fl
	}
	d.Unlock()
	// insert, and if final build it
	st, err = fl.Insert(ip)

	// at last, if we hit the maximum frag list len
	// without any defrag success, we just drop everything and
	// raise an error
	if st == false && fl.List.Len()+1 > IPv4MaximumFragmentListLen {
		d.Lock()
		fl = new(FragmentList)
		d.IPFlows[ipf] = fl
		d.Unlock()
		return false, fmt.Errorf("defrag: Fragment List hits its maximum"+
			"size(%d), without sucess. Flushing the list",
			IPv4MaximumFragmentListLen)
	}

	return st, err
}

// DiscardOlderThan forgets FragmentList without any activity since
// time t. It returns the number of FragmentList aka number of
// fragment packets it has discarded.
func (d *IPv4Defragmenter) DiscardOlderThan(t time.Time) int {
	var nb int
	d.Lock()
	for k, v := range d.IPFlows {
		if v.LastSeen.Before(t) {
			nb = nb + 1
			delete(d.IPFlows, k)
		}
	}
	d.Unlock()
	return nb
}

// DontDefrag returns true if the IPv4 packet do not need
// any defragmentation
func (d *IPv4Defragmenter) DontDefrag(ip *layers.IPv4) bool {
	// don't defrag packet with DF flag
	if ip.Flags&layers.IPv4DontFragment != 0 {
		return true
	}
	// don't defrag not fragmented ones
	if ip.Flags == 0 && ip.Id == 0 {
		return true
	}
	return false
}

// SecurityChecks performs the needed security checks
func (d *IPv4Defragmenter) SecurityChecks(ip *layers.IPv4) (bool, error) {
	// don't allow too big fragment offset
	if ip.FragOffset*8 > IPv4MaximumFragmentOffset {
		return false, fmt.Errorf("defrag: fragment offset too big "+
			"(handcrafted? %d > %d)", ip.FragOffset*8, IPv4MaximumFragmentOffset)
	}

	// don't allow fragment that would oversize an IP packet
	if ip.FragOffset*8+ip.Length > IPv4MaximumSize {
		return false, fmt.Errorf("defrag: fragment will overrun "+
			"(handcrafted? %d > %d)", ip.FragOffset*8+ip.Length, IPv4MaximumSize)
	}

	return true, nil
}

// FragmentList holds a container/list used to contains IP
// packets/fragments.  It stores internal counters to track the
// maximum total of byte, and the current length it has received.
// It also stores a flag to know if he has seen the last packet.
type FragmentList struct {
	List          list.List
	Total         uint16
	Current       uint16
	FinalReceived bool
	LastSeen      time.Time
}

// Insert insert an IPv4 fragment/packet into the Fragment List
// It use the following strategy : we are inserting fragment based
// on their offset, latest first. This is sometimes called BSD-Right.
// See: http://www.sans.org/reading-room/whitepapers/detection/ip-fragment-reassembly-scapy-33969
func (f *FragmentList) Insert(ip *layers.IPv4) (bool, error) {
	if ip.FragOffset*8 >= f.Total {
		f.List.PushBack(ip)
	} else {
		for e := f.List.Front(); e != nil; e = e.Next() {
			frag, _ := e.Value.(*layers.IPv4)
			if ip.FragOffset <= frag.FragOffset {
				debug.Printf("defrag: inserting frag %d before existing frag %d \n",
					ip.FragOffset*8, frag.FragOffset*8)
				f.List.InsertBefore(ip, e)
				break
			}
		}
	}
	// packet.Metadata().Timestamp should have been better, but
	// we don't have this info there...
	f.LastSeen = time.Now()

	fragLength := ip.Length - 20
	// After inserting the Fragment, we update the counters
	if f.Total < ip.FragOffset*8+fragLength {
		f.Total = ip.FragOffset*8 + fragLength
	}
	f.Current = f.Current + fragLength

	debug.Printf("defrag: insert ListLen: %d Total:%d Current:%d\n",
		f.List.Len(),
		f.Total, f.Current)

	// Final Fragment ?
	if ip.Flags&layers.IPv4MoreFragments == 0 {
		f.FinalReceived = true
	}
	// Ready to try defrag ?
	if f.FinalReceived && f.Total == f.Current {
		return f.Build(ip)
	}
	return false, nil
}

// Build builds the final datagram, modifying ip in place.
// It puts priority to packet in the early position of the list.
// See Insert for more details.
func (f *FragmentList) Build(ip *layers.IPv4) (bool, error) {
	var final []byte
	var currentOffset uint16 = 0

	debug.Printf("defrag: building the datagram \n")
	for e := f.List.Front(); e != nil; e = e.Next() {
		frag, _ := e.Value.(*layers.IPv4)
		if frag.FragOffset*8 == currentOffset {
			debug.Printf("defrag: building - adding %d\n", frag.FragOffset*8)
			final = append(final, frag.Payload...)
			currentOffset = currentOffset + frag.Length - 20
		} else if frag.FragOffset*8 < currentOffset {
			// overlapping fragment - let's take only what we need
			startAt := currentOffset - frag.FragOffset*8
			debug.Printf("defrag: building - overlapping, starting at %d\n",
				startAt)
			if startAt > frag.Length-20 {
				return false, fmt.Errorf("defrag: building - invalid fragment")
			}
			final = append(final, frag.Payload[startAt:]...)
			currentOffset = currentOffset + frag.FragOffset*8
		} else {
			// Houston - we have an hole !
			return false, nil
		}
		debug.Printf("defrag: building - next is %d\n", currentOffset)
	}

	// TODO recompute IP Checksum
	ip.Payload = final
	ip.Length = f.Total
	ip.FragOffset = 0
	ip.Flags = 0

	return true, nil
}

// IPv4Flow is a struct to be used as a key.
type IPv4Flow struct {
	net gopacket.Flow
	id  uint16
}

// NewIPv4Flow returns a new initialized IPv4Flow
func NewIPv4Flow(ip *layers.IPv4) *IPv4Flow {
	ipf := new(IPv4Flow)
	ipf.net = ip.NetworkFlow()
	ipf.id = ip.Id

	return ipf
}

// IPv4Defragmenter is a struct which embedded a map of
// all fragment/packet.
type IPv4Defragmenter struct {
	sync.RWMutex
	IPFlows map[IPv4Flow]*FragmentList
}

// NewIPv4Defragmenter returns a new IPv4Defragmenter
// with an initialized map.
func NewIPv4Defragmenter() *IPv4Defragmenter {
	d := new(IPv4Defragmenter)
	d.IPFlows = make(map[IPv4Flow]*FragmentList)

	return d
}
