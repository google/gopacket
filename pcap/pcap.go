// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcap

/*
#cgo linux LDFLAGS: -lpcap
#cgo freebsd LDFLAGS: -lpcap
#cgo darwin LDFLAGS: -lpcap
#cgo windows CFLAGS: -I C:/WpdPack/Include
#cgo windows,386 LDFLAGS: -L C:/WpdPack/Lib -lwpcap
#cgo windows,amd64 LDFLAGS: -L C:/WpdPack/Lib/x64 -lwpcap
#include <stdlib.h>
#include <pcap.h>

// Currently, there's a ton of old PCAP libs out there (including the default
// install on ubuntu machines) that don't support timestamps, so handle those.
#ifndef PCAP_TSTAMP_HOST
int pcap_set_tstamp_type(pcap_t* p, int t) { return -1; }
int pcap_list_tstamp_types(pcap_t* p, int** t) { return 0; }
const char* pcap_tstamp_type_val_to_name(int t) {
	return "pcap timestamp types not supported";
}
int pcap_tstamp_type_name_to_val(const char* t) {
	return PCAP_ERROR;
}
#endif
#ifndef PCAP_ERROR_PROMISC_PERM_DENIED
#define PCAP_ERROR_PROMISC_PERM_DENIED -11
#endif
*/
import "C"

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"errors"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const errorBufferSize = 256

// Handle provides a connection to a pcap handle, allowing users to read packets
// off the wire (Next), inject packets onto the wire (Inject), and
// perform a number of other functions to affect and understand packet output.
type Handle struct {
	// cptr is the handle for the actual pcap C object.
	cptr *C.pcap_t

	mu sync.Mutex
	// Since pointers to these objects are passed into a C function, if
	// they're declared locally then the Go compiler thinks they may have
	// escaped into C-land, so it allocates them on the heap.  This causes a
	// huge memory hit, so to handle that we store them here instead.
	pkthdr  *C.struct_pcap_pkthdr
	buf_ptr *C.u_char

	activate sync.Once
}

// Stats contains statistics on how many packets were handled by a pcap handle,
// and what was done with those packets.
type Stats struct {
	PacketsReceived  int
	PacketsDropped   int
	PacketsIfDropped int
}

// Interface describes a single network interface on a machine.
type Interface struct {
	Name        string
	Description string
	Addresses   []InterfaceAddress
	// TODO: add more elements
}

// InterfaceAddress describes an address associated with an Interface.
// Currently, it's IPv4/6 specific.
type InterfaceAddress struct {
	IP      net.IP
	Netmask net.IPMask
	// TODO: add broadcast + PtP dst ?
}

// BlockForever, when passed into OpenLive, causes it to block forever waiting for packets.
const BlockForever = time.Duration(0)

// OpenLive opens a device and returns a *Handle.
// It takes as arguments the name of the device ("eth0"), the maximum size to
// read for each packet (snaplen), whether to put the interface in promiscuous
// mode, and a timeout.
func OpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (handle *Handle, _ error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(errorBufferSize, 1))
	defer C.free(unsafe.Pointer(buf))
	var pro C.int
	if promisc {
		pro = 1
	}

	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	// This copies a bunch of the pcap_open_live implementation from pcap.c:
	cptr := C.pcap_create(dev, buf)
	if cptr == nil {
		return nil, errors.New(C.GoString(buf))
	}
	var status C.int
	if status = C.pcap_set_snaplen(cptr, C.int(snaplen)); status < 0 {
		goto fail
	} else if status = C.pcap_set_promisc(cptr, pro); status < 0 {
		goto fail
	} else if status = C.pcap_set_timeout(cptr, C.int(timeout/time.Millisecond)); status < 0 {
		goto fail
	}
	return newHandle(cptr), nil
fail:
	C.pcap_close(cptr)
	return nil, statusError(status)
}

func newHandle(cptr *C.pcap_t) (handle *Handle) {
	handle = &Handle{cptr: cptr}
	return
}

// OpenOffline opens a file and returns its contents as a *Handle.
func OpenOffline(file string) (handle *Handle, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(errorBufferSize, 1))
	defer C.free(unsafe.Pointer(buf))
	cf := C.CString(file)
	defer C.free(unsafe.Pointer(cf))

	cptr := C.pcap_open_offline(cf, buf)
	if cptr == nil {
		return nil, errors.New(C.GoString(buf))
	}
	h := newHandle(cptr)
	h.activate.Do(func() {}) // skip activation
	return h, nil
}

// NextError is the return code from a call to Next.
type NextError int32

// NextError implements the error interface.
func (n NextError) Error() string {
	switch n {
	case NextErrorOk:
		return "OK"
	case NextErrorTimeoutExpired:
		return "Timeout Expired"
	case NextErrorReadError:
		return "Read Error"
	case NextErrorNoMorePackets:
		return "No More Packets In File"
	}
	return strconv.Itoa(int(n))
}

const (
	NextErrorOk             NextError = 1
	NextErrorTimeoutExpired NextError = 0
	NextErrorReadError      NextError = -1
	// NextErrorNoMorePackets is returned when reading from a file (OpenOffline) and
	// EOF is reached.  When this happens, Next() returns io.EOF instead of this.
	NextErrorNoMorePackets NextError = -2
)

// NextError returns the next packet read from the pcap handle, along with an error
// code associated with that packet.  If the packet is read successfully, the
// returned error is nil.
func (p *Handle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	p.mu.Lock()
	err = p.getNextBufPtrLocked(&ci)
	if err == nil {
		data = C.GoBytes(unsafe.Pointer(p.buf_ptr), C.int(ci.CaptureLength))
	}
	p.mu.Unlock()
	return
}

func (p *Handle) activation() {
	C.pcap_activate(p.cptr)
}

// getNextBufPtrLocked is shared code for ReadPacketData and
// ZeroCopyReadPacketData.
func (p *Handle) getNextBufPtrLocked(ci *gopacket.CaptureInfo) error {
	p.activate.Do(p.activation)
	result := NextError(C.pcap_next_ex(p.cptr, &p.pkthdr, &p.buf_ptr))

	if result != NextErrorOk {
		if result == NextErrorNoMorePackets {
			return io.EOF
		} else {
			return result
		}
	}
	ci.Timestamp = time.Unix(int64(p.pkthdr.ts.tv_sec),
		int64(p.pkthdr.ts.tv_usec)*1000) // convert micros to nanos
	ci.CaptureLength = int(p.pkthdr.caplen)
	ci.Length = int(p.pkthdr.len)
	return nil
}

// ZeroCopyReadPacketData reads the next packet off the wire, and returns its data.
// The slice returned by ZeroCopyReadPacketData points to bytes owned by the
// the Handle.  Each call to ZeroCopyReadPacketData invalidates any data previously
// returned by ZeroCopyReadPacketData.  Care must be taken not to keep pointers
// to old bytes when using ZeroCopyReadPacketData... if you need to keep data past
// the next time you call ZeroCopyReadPacketData, use ReadPacketDataData, which copies
// the bytes into a new buffer for you.
//  data1, _, _ := handle.ZeroCopyReadPacketData()
//  // do everything you want with data1 here, copying bytes out of it if you'd like to keep them around.
//  data2, _, _ := handle.ZeroCopyReadPacketData()  // invalidates bytes in data1
func (p *Handle) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	p.mu.Lock()
	err = p.getNextBufPtrLocked(&ci)
	if err == nil {
		slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
		slice.Data = uintptr(unsafe.Pointer(p.buf_ptr))
		slice.Len = ci.CaptureLength
		slice.Cap = ci.CaptureLength
	}
	p.mu.Unlock()
	return
}

// Close closes the underlying pcap handle.
func (p *Handle) Close() {
	C.pcap_close(p.cptr)
}

// Error returns the current error associated with a pcap handle (pcap_geterr).
func (p *Handle) Error() error {
	return errors.New(C.GoString(C.pcap_geterr(p.cptr)))
}

// Stats returns statistics on the underlying pcap handle.
func (p *Handle) Stats() (stat *Stats, err error) {
	var cstats _Ctype_struct_pcap_stat
	if -1 == C.pcap_stats(p.cptr, &cstats) {
		return nil, p.Error()
	}
	return &Stats{
		PacketsReceived:  int(cstats.ps_recv),
		PacketsDropped:   int(cstats.ps_drop),
		PacketsIfDropped: int(cstats.ps_ifdrop),
	}, nil
}

// SetBPFFilter compiles and sets a BPF filter for the pcap handle.
func (p *Handle) SetBPFFilter(expr string) (err error) {
	p.activate.Do(p.activation)
	var bpf _Ctype_struct_bpf_program
	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	if -1 == C.pcap_compile(p.cptr, &bpf, cexpr, 1, 0) {
		return p.Error()
	}

	if -1 == C.pcap_setfilter(p.cptr, &bpf) {
		C.pcap_freecode(&bpf)
		return p.Error()
	}
	C.pcap_freecode(&bpf)
	return nil
}

// Version returns pcap_lib_version.
func Version() string {
	return C.GoString(C.pcap_lib_version())
}

// LinkType returns pcap_datalink, as a layers.LinkType.
func (p *Handle) LinkType() layers.LinkType {
	return layers.LinkType(C.pcap_datalink(p.cptr))
}

// SetLinkType calls pcap_set_datalink on the pcap handle.
func (p *Handle) SetLinkType(dlt layers.LinkType) error {
	if -1 == C.pcap_set_datalink(p.cptr, C.int(dlt)) {
		return p.Error()
	}
	return nil
}

// FindAllDevs attempts to enumerate all interfaces on the current machine.
func FindAllDevs() (ifs []Interface, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(errorBufferSize, 1))
	defer C.free(unsafe.Pointer(buf))
	var alldevsp *C.pcap_if_t

	if -1 == C.pcap_findalldevs((**C.pcap_if_t)(&alldevsp), buf) {
		return nil, errors.New(C.GoString(buf))
	}
	defer C.pcap_freealldevs((*C.pcap_if_t)(alldevsp))
	dev := alldevsp
	var i uint32
	for i = 0; dev != nil; dev = (*C.pcap_if_t)(dev.next) {
		i++
	}
	ifs = make([]Interface, i)
	dev = alldevsp
	for j := uint32(0); dev != nil; dev = (*C.pcap_if_t)(dev.next) {
		var iface Interface
		iface.Name = C.GoString(dev.name)
		iface.Description = C.GoString(dev.description)
		iface.Addresses = findalladdresses(dev.addresses)
		// TODO: add more elements
		ifs[j] = iface
		j++
	}
	return
}

func findalladdresses(addresses *_Ctype_struct_pcap_addr) (retval []InterfaceAddress) {
	// TODO - make it support more than IPv4 and IPv6?
	retval = make([]InterfaceAddress, 0, 1)
	for curaddr := addresses; curaddr != nil; curaddr = (*_Ctype_struct_pcap_addr)(curaddr.next) {
		var a InterfaceAddress
		var err error
		if a.IP, err = sockaddr_to_IP((*syscall.RawSockaddr)(unsafe.Pointer(curaddr.addr))); err != nil {
			continue
		}
		if a.Netmask, err = sockaddr_to_IP((*syscall.RawSockaddr)(unsafe.Pointer(curaddr.addr))); err != nil {
			continue
		}
		retval = append(retval, a)
	}
	return
}

func sockaddr_to_IP(rsa *syscall.RawSockaddr) (IP []byte, err error) {
	switch rsa.Family {
	case syscall.AF_INET:
		pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		IP = make([]byte, 4)
		for i := 0; i < len(IP); i++ {
			IP[i] = pp.Addr[i]
		}
		return
	case syscall.AF_INET6:
		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		IP = make([]byte, 16)
		for i := 0; i < len(IP); i++ {
			IP[i] = pp.Addr[i]
		}
		return
	}
	err = errors.New("Unsupported address type")
	return
}

// WritePacketData calls pcap_sendpacket, injecting the given data into the pcap handle.
func (p *Handle) WritePacketData(data []byte) (err error) {
	p.activate.Do(p.activation)
	buf := C.CString(string(data))
	defer C.free(unsafe.Pointer(buf))

	if -1 == C.pcap_sendpacket(p.cptr, (*C.u_char)(unsafe.Pointer(buf)), (C.int)(len(data))) {
		err = p.Error()
	}
	return
}

// TimestampSource tells PCAP which type of timestamp to use for packets.
type TimestampSource C.int

// String returns the timestamp type as a human-readable string.
func (t TimestampSource) String() string {
	return C.GoString(C.pcap_tstamp_type_val_to_name(C.int(t)))
}

// TimestampSourceFromString translates a string into a timestamp type, case
// insensitive.
func TimestampSourceFromString(s string) (TimestampSource, error) {
	t := C.pcap_tstamp_type_name_to_val(C.CString(s))
	if t < 0 {
		return 0, statusError(t)
	}
	return TimestampSource(t), nil
}

func statusError(status C.int) error {
	return errors.New(C.GoString(C.pcap_statustostr(status)))
}

// SupportedTimestamps returns a list of supported timstamp types for this
// handle.
func (p *Handle) SupportedTimestamps() (out []TimestampSource) {
	var types *C.int
	n := int(C.pcap_list_tstamp_types(p.cptr, &types))
	defer C.free(unsafe.Pointer(types))
	typesArray := (*[100]C.int)(unsafe.Pointer(types))
	for i := 0; i < n; i++ {
		out = append(out, TimestampSource((*typesArray)[i]))
	}
	return
}

// SetTimestampSource sets the type of timestamp generator PCAP uses when
// attaching timestamps to packets.
func (p *Handle) SetTimestampSource(t TimestampSource) error {
	if status := C.pcap_set_tstamp_type(p.cptr, C.int(t)); status < 0 {
		return statusError(status)
	}
	return nil
}
