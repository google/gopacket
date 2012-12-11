// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

/*
#cgo LDFLAGS: -lpcap
#include <stdlib.h>
#include <pcap.h>

// Workaround for not knowing how to cast to const u_char**
int hack_pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
                      u_char **pkt_data) {
    return pcap_next_ex(p, pkt_header, (const u_char **)pkt_data);
}
*/
import "C"
import (
	"errors"
	"net"
	"syscall"
	"time"
	"unsafe"
)

type PcapHandle struct {
	cptr *C.pcap_t
}

type PcapStats struct {
	PacketsReceived  uint32
	PacketsDropped   uint32
	PacketsIfDropped uint32
}

type PcapInterface struct {
	Name        string
	Description string
	Addresses   []PcapIFAddress
	// TODO: add more elements
}

type PcapIFAddress struct {
	IP      net.IP
	Netmask net.IPMask
	// TODO: add broadcast + PtP dst ?
}

func (p *PcapHandle) Next() (pkt *Packet) {
	rv, _ := p.NextEx()
	return rv
}

// OpenLivePcap opens a device and returns a *PcapHandle
func OpenLivePcap(device string, snaplen int32, promisc bool, timeout_ms int32) (handle *PcapHandle, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	h := new(PcapHandle)
	var pro int32
	if promisc {
		pro = 1
	}

	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	h.cptr = C.pcap_open_live(dev, C.int(snaplen), C.int(pro), C.int(timeout_ms), buf)
	if nil == h.cptr {
		handle = nil
		err = errors.New(C.GoString(buf))
	} else {
		handle = h
	}
	C.free(unsafe.Pointer(buf))
	return
}

// OpenOfflinePcap opens a file and returns its contents as a *PcapHandle
func OpenOfflinePcap(file string) (handle *PcapHandle, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	h := new(PcapHandle)

	cf := C.CString(file)
	defer C.free(unsafe.Pointer(cf))

	h.cptr = C.pcap_open_offline(cf, buf)
	if nil == h.cptr {
		handle = nil
		err = errors.New(C.GoString(buf))
	} else {
		handle = h
	}
	C.free(unsafe.Pointer(buf))
	return
}

type PcapResultCode int32

const (
  PcapResultOk PcapResultCode = 1
	PcapResultTimeoutExpired PcapResultCode = 0
	PcapResultReadError = -1
	PcapResultNoMorePackets = -2
)


func (p *PcapHandle) NextEx() (pkt *Packet, result PcapResultCode) {
	var pkthdr *C.struct_pcap_pkthdr

	var buf_ptr *C.u_char
	var buf unsafe.Pointer
	result = PcapResultCode(C.hack_pcap_next_ex(p.cptr, &pkthdr, &buf_ptr))

	buf = unsafe.Pointer(buf_ptr)

	if nil == buf {
		return
	}
	pkt = new(Packet)
	pkt.Time = time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec))
	pkt.Caplen = uint32(pkthdr.caplen)
	pkt.Len = uint32(pkthdr.len)
	pkt.Data = C.GoBytes(buf, C.int(pcthdr.caplen))
	return
}

func (p *PcapHandle) Close() {
	C.pcap_close(p.cptr)
}

func (p *PcapHandle) GetError() error {
	return errors.New(C.GoString(C.pcap_geterr(p.cptr)))
}

func (p *PcapHandle) GetStats() (stat *PcapStats, err error) {
	var cstats _Ctype_struct_pcap_stat
	if -1 == C.pcap_stats(p.cptr, &cstats) {
		return nil, p.GetError()
	}
	stats := new(PcapStats)
	stats.PacketsReceived = uint32(cstats.ps_recv)
	stats.PacketsDropped = uint32(cstats.ps_drop)
	stats.PacketsIfDropped = uint32(cstats.ps_ifdrop)

	return stats, nil
}

func (p *PcapHandle) SetFilter(expr string) (err error) {
	var bpf _Ctype_struct_bpf_program
	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	if -1 == C.pcap_compile(p.cptr, &bpf, cexpr, 1, 0) {
		return p.GetError()
	}

	if -1 == C.pcap_setfilter(p.cptr, &bpf) {
		C.pcap_freecode(&bpf)
		return p.GetError()
	}
	C.pcap_freecode(&bpf)
	return nil
}

func Version() string {
	return C.GoString(C.pcap_lib_version())
}

func (p *PcapHandle) LinkType() LinkType {
	return LinkType(C.pcap_datalink(p.cptr))
}

func (p *PcapHandle) SetLinkType(dlt LinkType) error {
	if -1 == C.pcap_set_datalink(p.cptr, C.int(dlt)) {
		return p.GetError()
	}
	return nil
}

func FindAllDevs() (ifs []PcapInterface, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
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
	ifs = make([]PcapInterface, i)
	dev = alldevsp
	for j := uint32(0); dev != nil; dev = (*C.pcap_if_t)(dev.next) {
		var iface PcapInterface
		iface.Name = C.GoString(dev.name)
		iface.Description = C.GoString(dev.description)
		iface.Addresses = findalladdresses(dev.addresses)
		// TODO: add more elements
		ifs[j] = iface
		j++
	}
	return
}

func findalladdresses(addresses *_Ctype_struct_pcap_addr) (retval []PcapIFAddress) {
	// TODO - make it support more than IPv4 and IPv6?
	retval = make([]PcapIFAddress, 0, 1)
	for curaddr := addresses; curaddr != nil; curaddr = (*_Ctype_struct_pcap_addr)(curaddr.next) {
		var a PcapIFAddress
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

func (p *PcapHandle) Inject(data []byte) (err error) {
	buf := (*C.char)(C.malloc((C.size_t)(len(data))))

	for i := 0; i < len(data); i++ {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(buf)) + uintptr(i))) = data[i]
	}

	if -1 == C.pcap_inject(p.cptr, unsafe.Pointer(buf), (C.size_t)(len(data))) {
		err = p.GetError()
	}
	C.free(unsafe.Pointer(buf))
	return
}
