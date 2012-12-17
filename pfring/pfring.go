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
	"os"
	"strconv"
	"time"
	"unsafe"
)

const errorBufferSize = 256

// Ring provides a handle to a pf_ring.
type Ring struct {
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

// NewRing creates a new PFRing.  Note that when the ring is initially created,
// it is disabled.  The caller must call Enable to start receiving packets.
// The caller should call Close on the given ring when finished with it.
func NewRing(device string, snaplen uint32, flags Flag) (ring *Ring, _ error) {
	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	cptr := C.pfring_open(dev, C.u_int32_t(snaplen), C.u_int32_t(flags))
	if cptr == nil {
		return nil, errors.New("PFRing failure")
	}
	ring = &Ring{cptr: cptr, snaplen: int(snaplen)}
	ring.SetApplicationName(os.Args[0])
	return
}

// Close closes the given Ring.  After this call, the Ring should no longer be
// used.
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
func (r *Ring) NextPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	var pkthdr C.struct_pfring_pkthdr

	data = make([]byte, r.snaplen)
	// This tricky buf_ptr points to the start of our slice data, so pfring_recv
	// will actually write directly into our Go slice.  Nice!
	var buf_ptr *C.u_char = (*C.u_char)(unsafe.Pointer(&data[0]))
	result := NextResult(C.pfring_recv(r.cptr, &buf_ptr, C.u_int(r.snaplen), &pkthdr, 1))
	if result != NextOk {
		err = result
		data = nil
		return
	}
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

// SetCluster sets which cluster the ring should be part of, and the cluster
// type to use.
func (r *Ring) SetCluster(cluster int, typ ClusterType) error {
	if rv := C.pfring_set_cluster(r.cptr, C.u_int(cluster), C.cluster_type(typ)); rv != 0 {
		return fmt.Errorf("Unable to set cluster, got error code %d", rv)
	}
	return nil
}

// RemoveFromCluster removes the ring from the cluster it was put in with
// SetCluster.
func (r *Ring) RemoveFromCluster() error {
	if rv := C.pfring_remove_from_cluster(r.cptr); rv != 0 {
		return fmt.Errorf("Unable to remove from cluster, got error code %d", rv)
	}
	return nil
}

// SetSamplingRate sets the sampling rate to 1/<rate>.
func (r *Ring) SetSamplingRate(rate int) error {
	if rv := C.pfring_set_sampling_rate(r.cptr, C.u_int32_t(rate)); rv != 0 {
		return fmt.Errorf("Unable to set sampling rate, got error code %d", rv)
	}
	return nil
}

// SetBPFFilter sets the BPF filter for the ring.
func (r *Ring) SetBPFFilter(bpf_filter string) error {
	filter := C.CString(bpf_filter)
	defer C.free(unsafe.Pointer(filter))
	if rv := C.pfring_set_bpf_filter(r.cptr, filter); rv != 0 {
		return fmt.Errorf("Unable to set BPF filter, got error code %d", rv)
	}
	return nil
}

// RemoveBPFFilter removes the BPF filter from the ring.
func (r *Ring) RemoveBPFFilter() error {
	if rv := C.pfring_remove_bpf_filter(r.cptr); rv != 0 {
		return fmt.Errorf("Unable to remove BPF filter, got error code %d", rv)
	}
	return nil
}

// Inject uses the ring to send raw packet data to the interface.
func (r *Ring) Inject(data []byte) error {
	buf := (*C.char)(unsafe.Pointer(&data[0]))
	if rv := C.pfring_send(r.cptr, buf, C.u_int(len(data)), 1); rv != 0 {
		return fmt.Errorf("Unable to send packet data, got error code %d", rv)
	}
	return nil
}

// Enable enables the given ring.  This function MUST be called on each new
// ring after it has been set up, or that ring will NOT receive packets.
func (r *Ring) Enable() error {
	if rv := C.pfring_enable_ring(r.cptr); rv != 0 {
		return fmt.Errorf("Unable to enable ring, got error code %d", rv)
	}
	return nil
}

// Disable disables the given ring.  After this call, it will no longer receive
// packets.
func (r *Ring) Disable() error {
	if rv := C.pfring_disable_ring(r.cptr); rv != 0 {
		return fmt.Errorf("Unable to disable ring, got error code %d", rv)
	}
	return nil
}

type Stats struct {
	Received, Dropped uint64
}

// Stats returns statistsics for the ring.
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
	// TransmitOnly will only capture packets transmitted by the ring's
	// interface(s).
	TransmitOnly Direction = C.tx_only_direction
	// ReceiveOnly will only capture packets received by the ring's
	// interface(s).
	ReceiveOnly Direction = C.rx_only_direction
	// ReceiveAndTransmit will capture both received and transmitted packets on
	// the ring's interface(s).
	ReceiveAndTransmit Direction = C.rx_and_tx_direction
)

// SetDirection sets which packets should be captured by the ring.
func (r *Ring) SetDirection(d Direction) error {
	if rv := C.pfring_set_direction(r.cptr, C.packet_direction(d)); rv != 0 {
		return fmt.Errorf("Unable to set ring direction, got error code %d", rv)
	}
	return nil
}

type SocketMode C.socket_mode

const (
	// SendOnly sets up the ring to only send packets (Inject), not read them.
	SendOnly SocketMode = C.send_only_mode
	// ReceiveOnly sets up the ring to only receive packets (NextPacketData), not
	// send them.
	ReceiveOnly SocketMode = C.recv_only_mode
	// SendAndReceive sets up the ring to both send and receive packets.
	SendAndReceive SocketMode = C.send_and_recv_mode
)

// SetSocketMode sets the mode of the ring socket to send, receive, or both.
func (r *Ring) SetSocketMode(s SocketMode) error {
	if rv := C.pfring_set_socket_mode(r.cptr, C.socket_mode(s)); rv != 0 {
		return fmt.Errorf("Unable to set socket mode, got error code %d", rv)
	}
	return nil
}

// SetApplicationName sets a string name to the ring.  This name is available in
// /proc stats for pf_ring.  By default, NewRing automatically calls this with
// argv[0].
func (r *Ring) SetApplicationName(name string) error {
	buf := C.CString(name)
	defer C.free(unsafe.Pointer(buf))
	if rv := C.pfring_set_application_name(r.cptr, buf); rv != 0 {
		return fmt.Errorf("Unable to set ring application name, got error code %d", rv)
	}
	return nil
}
