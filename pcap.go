package pcap

/*
struct pcap { int dummy; };
#include <stdlib.h>
#include <pcap.h>
*/
import "C"
import (
	"unsafe"
)

const (
	ERRBUF_SIZE = 256

	// according to pcap-linktype(7)
	LINKTYPE_NULL             = 0
	LINKTYPE_ETHERNET         = 1
	LINKTYPE_TOKEN_RING       = 6
	LINKTYPE_ARCNET           = 7
	LINKTYPE_SLIP             = 8
	LINKTYPE_PPP              = 9
	LINKTYPE_FDDI             = 10
	LINKTYPE_ATM_RFC1483      = 100
	LINKTYPE_RAW              = 101
	LINKTYPE_PPP_HDLC         = 50
	LINKTYPE_PPP_ETHER        = 51
	LINKTYPE_C_HDLC           = 104
	LINKTYPE_IEEE802_11       = 105
	LINKTYPE_FRELAY           = 107
	LINKTYPE_LOOP             = 108
	LINKTYPE_LINUX_SLL        = 113
	LINKTYPE_LTALK            = 104
	LINKTYPE_PFLOG            = 117
	LINKTYPE_PRISM_HEADER     = 119
	LINKTYPE_IP_OVER_FC       = 122
	LINKTYPE_SUNATM           = 123
	LINKTYPE_IEEE802_11_RADIO = 127
	LINKTYPE_ARCNET_LINUX     = 129
	LINKTYPE_LINUX_IRDA       = 144
	LINKTYPE_LINUX_LAPD       = 177
)

type Pcap struct {
	cptr *C.pcap_t
}

type Packet struct {
	Time struct {
		Sec  int32
		Usec int32
	}
	Caplen uint32
	Len    uint32
	Data   []byte
}

type Stat struct {
	PacketsReceived  uint32
	PacketsDropped   uint32
	PacketsIfDropped uint32
}

type Interface struct {
	Name        string
	Description string
	// TODO: add more elements
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
	var pkthdr _Ctype_struct_pcap_pkthdr
	var buf unsafe.Pointer
	buf = unsafe.Pointer(C.pcap_next(p.cptr, &pkthdr))
	if nil == buf {
		return nil
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
	var alldevsp *_Ctypedef_pcap_if_t

	if -1 == C.pcap_findalldevs((**C.pcap_if_t)(&alldevsp), buf) {
		ifs = nil
		err = C.GoString(buf)
	} else {
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
			// TODO: add more elements
			ifs[j] = iface
			j++
		}
		C.pcap_freealldevs((*C.pcap_if_t)(alldevsp))
	}
	C.free(unsafe.Pointer(buf))
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
