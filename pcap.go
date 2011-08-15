package pcap

/*
struct pcap { int dummy; };
#include <stdlib.h>
#include <pcap.h>
*/
import "C"
import (
	"unsafe"
	"os"
	"net"
	"syscall"
)

type Pcap struct {
	cptr *C.pcap_t
}

type Stat struct {
	PacketsReceived  uint32
	PacketsDropped   uint32
	PacketsIfDropped uint32
}

type Interface struct {
	Name        string
	Description string
	Addresses   []IFAddress
	// TODO: add more elements
}

type IFAddress struct {
	IP      net.IP
	Netmask net.IPMask
	// TODO: add broadcast + PtP dst ?
}

func Openlive(device string, snaplen int32, promisc bool, timeout_ms int32) (handle *Pcap, err string) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	h := new(Pcap)
	var pro int32
	if promisc {
		pro = 1
	} else {
		pro = 0
	}
	h.cptr = C.pcap_open_live(C.CString(device), C.int(snaplen), C.int(pro), C.int(timeout_ms), buf)
	if nil == h.cptr {
		handle = nil
		err = C.GoString(buf)
	} else {
		handle = h
	}
	C.free(unsafe.Pointer(buf))
	return
}

func Openoffline(file string) (handle *Pcap, err string) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	h := new(Pcap)
	h.cptr = C.pcap_open_offline(C.CString(file), buf)
	if nil == h.cptr {
		handle = nil
		err = C.GoString(buf)
	} else {
		handle = h
	}
	C.free(unsafe.Pointer(buf))
	return
}

func (p *Pcap) Next() (pkt *Packet) {
	rv, _ := p.NextEx()

	return rv
}

func (p *Pcap) NextEx() (pkt *Packet, result int32) {
	var pkthdr_ptr *_Ctype_struct_pcap_pkthdr
	var pkthdr _Ctype_struct_pcap_pkthdr

	var buf_ptr *_Ctypedef_u_char
	var buf unsafe.Pointer
	result = int32(C.pcap_next_ex(p.cptr, &pkthdr_ptr, &buf_ptr))

	buf = unsafe.Pointer(buf_ptr)
	pkthdr = *pkthdr_ptr

	if nil == buf {
		pkt = nil
		return
	}
	pkt = new(Packet)
	pkt.Time.Sec = int32(pkthdr.ts.tv_sec)
	pkt.Time.Usec = int32(pkthdr.ts.tv_usec)
	pkt.Caplen = uint32(pkthdr.caplen)
	pkt.Len = uint32(pkthdr.len)
	pkt.Data = make([]byte, pkthdr.caplen)

	for i := uint32(0); i < pkt.Caplen; i++ {
		pkt.Data[i] = *(*byte)(unsafe.Pointer(uintptr(buf) + uintptr(i)))
	}

	return
}

func (p *Pcap) Geterror() string {
	return C.GoString(C.pcap_geterr(p.cptr))
}

func (p *Pcap) Getstats() (stat *Stat, err string) {
	var cstats _Ctype_struct_pcap_stat
	if -1 == C.pcap_stats(p.cptr, &cstats) {
		return nil, p.Geterror()
	}

	stats := new(Stat)

	stats.PacketsReceived = uint32(cstats.ps_recv)
	stats.PacketsDropped = uint32(cstats.ps_drop)
	stats.PacketsIfDropped = uint32(cstats.ps_ifdrop)

	return stats, ""
}

func (p *Pcap) Setfilter(expr string) (err string) {
	var bpf _Ctype_struct_bpf_program

	if -1 == C.pcap_compile(p.cptr, &bpf, C.CString(expr), 1, 0) {
		return p.Geterror()
	}

	if -1 == C.pcap_setfilter(p.cptr, &bpf) {
		C.pcap_freecode(&bpf)
		return p.Geterror()
	}

	C.pcap_freecode(&bpf)
	return ""
}

func Version() string {
	return C.GoString(C.pcap_lib_version())
}

func (p *Pcap) Datalink() int {
	return int(C.pcap_datalink(p.cptr))
}

func (p *Pcap) Setdatalink(dlt int) string {
	if -1 == C.pcap_set_datalink(p.cptr, C.int(dlt)) {
		return p.Geterror()
	}
	return ""
}

func DatalinkValueToName(dlt int) string {
	name := C.pcap_datalink_val_to_name(C.int(dlt))
	if nil != name {
		return C.GoString(name)
	}
	return ""
}

func DatalinkValueToDescription(dlt int) string {
	desc := C.pcap_datalink_val_to_description(C.int(dlt))
	if nil != desc {
		return C.GoString(desc)
	}
	return ""
}

func Findalldevs() (ifs []Interface, err string) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))
	var alldevsp *_Ctypedef_pcap_if_t

	if -1 == C.pcap_findalldevs((**C.pcap_if_t)(&alldevsp), buf) {
		return nil, C.GoString(buf)
	}
	defer C.pcap_freealldevs((*C.pcap_if_t)(alldevsp))
	dev := alldevsp
	var i uint32
	for i = 0; dev != nil; dev = (*_Ctypedef_pcap_if_t)(dev.next) {
		i++
	}
	ifs = make([]Interface, i)
	dev = alldevsp
	for j := uint32(0); dev != nil; dev = (*_Ctypedef_pcap_if_t)(dev.next) {
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

func findalladdresses(addresses *_Ctype_struct_pcap_addr) (retval []IFAddress) {
	// TODO - make it support more than IPv4 and IPv6?
	retval = make([]IFAddress, 0, 1)
	for curaddr := addresses; curaddr != nil; curaddr = (*_Ctype_struct_pcap_addr)(curaddr.next) {
		var a IFAddress
		var err os.Error
		a.IP, err = sockaddr_to_IP((*syscall.RawSockaddr)(unsafe.Pointer(curaddr.addr)))
		if err != nil {
			continue
		}
		a.Netmask, err = sockaddr_to_IP((*syscall.RawSockaddr)(unsafe.Pointer(curaddr.addr)))
		if err != nil {
			continue
		}
		retval = append(retval, a)
	}
	return
}

func sockaddr_to_IP(rsa *syscall.RawSockaddr) (IP []byte, err os.Error) {
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
	err = os.NewError("Unsupported address type")
	return
}

func (p *Pcap) Inject(data []byte) (err string) {
	buf := (*C.char)(C.malloc((C.size_t)(len(data))))

	for i := 0; i < len(data); i++ {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(buf)) + uintptr(i))) = data[i]
	}

	if -1 == C.pcap_inject(p.cptr, unsafe.Pointer(buf), (C.size_t)(len(data))) {
		err = p.Geterror()
	}
	C.free(unsafe.Pointer(buf))
	return
}
