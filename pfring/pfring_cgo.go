// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package pfring

/*
#cgo LDFLAGS: -lpfring -lpcap
#include <stdlib.h>
#include <pfring.h>
#include <linux/pf_ring.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"github.com/gconnell/gopacket"
	"strconv"
	"time"
	"unsafe"
)

const errorBufferSize = 256

// Ring provides a handle to a pf_ring.
type Ring struct {
	// DecodeOptions is used by the handle to determine how each packet should be
	// decoded.  Once the handle is created, you may change DecodeOptions at any
	// time, and the results will take affect on the next Next call.
	DecodeOptions gopacket.DecodeOptions
	// Decoder determines the algorithm used for decoding each packet.  It
	// defaults to the gopacket.LinkType associated with this Handle.
	Decoder gopacket.Decoder
	// cptr is the handle for the actual pcap C object.
	cptr    *C.pfring
	snaplen int
}

type Flag uint32

const (
	FlagReentrant       Flag = C.PF_RING_REENTRANT
	FlagLongHeader      Flag = C.PF_RING_LONG_HEADER
	FlagPromisc         Flag = C.PF_RING_PROMISC
	FlagDNASymmetricRSS Flag = C.PF_RING_DNA_SYMMETRIC_RSS
	FlagTimestamp       Flag = C.PF_RING_TIMESTAMP
	FlagHWTimestamp     Flag = C.PF_RING_HW_TIMESTAMP
)

func Open(device string, snaplen uint32, flags Flag) (ring *Ring, _ error) {
	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	cptr := C.pfring_open(dev, C.u_int32_t(snaplen), C.u_int32_t(flags))
	if cptr == nil {
		return nil, errors.New("PFRing failure")
	}
	return &Ring{cptr: cptr, snaplen: int(snaplen)}, nil
}

func (r *Ring) Close() {
	C.pfring_close(r.cptr)
}

// NextResult is the return code from a call to Next.
type NextResult int32

const (
	NextNoPacketNonblocking NextResult = 0
	NextError               NextResult = -1
	NextOk                  NextResult = 1
)

// NextResult implements the error interface.
func (n NextResult) Error() string {
	return strconv.Itoa(int(n))
}

// NextResult returns the next packet read from the pcap handle, along with an error
// code associated with that packet.  If the packet is read successfully, the
// returned error is nil.
func (r *Ring) internalNext() (data []byte, ci gopacket.CaptureInfo, err error) {
	var pkthdr C.struct_pfring_pkthdr

	var buf unsafe.Pointer = C.malloc(C.size_t(r.snaplen))
	var buf_ptr *C.u_char = (*C.u_char)(buf)
	defer C.free(buf)
	result := NextResult(C.pfring_recv(r.cptr, &buf_ptr, C.u_int(r.snaplen), &pkthdr, 1))
	if result != NextOk {
		err = result
		return
	}
	// BUG(gconnell):  This currently does an extra copy of packet data... if we
	// can figure out a way to pass a pointer to a slice address space into
	// pfring_recv above, the pfring will write into the slice, instead of us
	// having to copy it.
	data = C.GoBytes(buf, C.int(pkthdr.caplen))
	ci.Populated = true
	ci.Timestamp = time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec))
	ci.CaptureLength = int(pkthdr.caplen)
	ci.Length = int(pkthdr.len)
	return
}

type ClusterType C.cluster_type

const (
	ClusterPerFlow          ClusterType = C.cluster_per_flow
	ClusterRoundRobin       ClusterType = C.cluster_round_robin
	ClusterPerFlow2Tuple    ClusterType = C.cluster_per_flow_2_tuple
	ClusterPerFlow4Tuple    ClusterType = C.cluster_per_flow_4_tuple
	ClusterPerFlow5Tuple    ClusterType = C.cluster_per_flow_5_tuple
	ClusterPerFlowTCP5Tuple ClusterType = C.cluster_per_flow_tcp_5_tuple
)

func (r *Ring) SetCluster(cluster int, typ ClusterType) error {
	if rv := C.pfring_set_cluster(r.cptr, C.u_int(cluster), C.cluster_type(typ)); rv != 0 {
		return fmt.Errorf("Unable to set cluster, got error code %d", rv)
	}
	return nil
}

func (r *Ring) RemoveFromCluster() error {
	if rv := C.pfring_remove_from_cluster(r.cptr); rv != 0 {
		return fmt.Errorf("Unable to remove from cluster, got error code %d", rv)
	}
	return nil
}

func (r *Ring) SetSamplingRate(rate int) error {
	if rv := C.pfring_set_sampling_rate(r.cptr, C.u_int32_t(rate)); rv != 0 {
		return fmt.Errorf("Unable to set sampling rate, got error code %d", rv)
	}
	return nil
}

func (r *Ring) SetBPFFilter(bpf_filter string) error {
	filter := C.CString(bpf_filter)
	defer C.free(unsafe.Pointer(filter))
	if rv := C.pfring_set_bpf_filter(r.cptr, filter); rv != 0 {
		return fmt.Errorf("Unable to set BPF filter, got error code %d", rv)
	}
	return nil
}

func (r *Ring) RemoveBPFFilter() error {
	if rv := C.pfring_remove_bpf_filter(r.cptr); rv != 0 {
		return fmt.Errorf("Unable to remove BPF filter, got error code %d", rv)
	}
	return nil
}

func (r *Ring) Inject(data []byte) error {
	buf := C.CString(string(data))
	defer C.free(unsafe.Pointer(buf))

	if rv := C.pfring_send(r.cptr, buf, C.u_int(len(data)), 1); rv != 0 {
		return fmt.Errorf("Unable to send packet data, got error code %d", rv)
	}
	return nil
}

func (r *Ring) Enable() error {
	if rv := C.pfring_enable_ring(r.cptr); rv != 0 {
		return fmt.Errorf("Unable to enable ring, got error code %d", rv)
	}
	return nil
}

func (r *Ring) Disable() error {
	if rv := C.pfring_disable_ring(r.cptr); rv != 0 {
		return fmt.Errorf("Unable to disable ring, got error code %d", rv)
	}
	return nil
}

type Stats struct {
	Received, Dropped uint64
}

func (r *Ring) Stats() (s Stats, err error) {
	var stats C.pfring_stat
	if rv := C.pfring_stats(r.cptr, &stats); rv != 0 {
		err = fmt.Errorf("Unable to get ring stats, got error code %d", rv)
		return
	}
	s.Received = uint64(stats.recv)
	s.Dropped = uint64(stats.drop)
	return
}

type Direction C.packet_direction

const (
	TXOnly  Direction = C.tx_only_direction
	RXOnly  Direction = C.rx_only_direction
	RXAndTX Direction = C.rx_and_tx_direction
)

func (r *Ring) SetDirection(d Direction) error {
	if rv := C.pfring_set_direction(r.cptr, C.packet_direction(d)); rv != 0 {
		return fmt.Errorf("Unable to set ring direction, got error code %d", rv)
	}
	return nil
}
