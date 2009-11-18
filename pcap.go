package pcap

/*
struct pcap { int dummy; };
#include <stdlib.h>
#include <pcap.h>
*/
import "C";
import (
	"bytes";
	"syscall";
	"unsafe";
)

const (
	ERRBUF_SIZE = 256;
)

type Pcap struct {
	cptr *C.pcap_t;
}

type Packet struct {
	Time syscall.Timeval;
	Caplen uint32;
	Len uint32;
	Data []byte;
}

func Openlive(device string, snaplen int32, promisc bool, timeout_ms int32) (handle *Pcap, err string) {
	buf := make([]byte, ERRBUF_SIZE);
	h := new(Pcap);
	var pro int32;
	if promisc { pro = 1 } else { pro = 0 }
	h.cptr = C.pcap_open_live(C.CString(device), C.int(snaplen), C.int(pro), C.int(timeout_ms), C.CString(bytes.NewBuffer(buf).String()));
	if nil == h.cptr {
		handle = nil;
		err = bytes.NewBuffer(buf).String();
		return;
	}
	handle = h;
	return;
}

func Openoffline(file string) (handle *Pcap, err string) {
	buf := make([]byte, ERRBUF_SIZE);
	h := new(Pcap);
	h.cptr = C.pcap_open_offline(C.CString(file), C.CString(bytes.NewBuffer(buf).String()));
	if nil == h.cptr {
		handle = nil;
		// err = bytes.NewBuffer(buf).String();
		return;
	}
	handle = h;
	return;
}

func(p *Pcap) Next() (pkt *Packet) {
	var pkthdr _Cstruct_pcap_pkthdr;
	var buf unsafe.Pointer;
	buf = unsafe.Pointer(C.pcap_next(p.cptr, &pkthdr));
	if nil == buf {
		return nil;
	}
	pkt = new(Packet);
	pkt.Time.Sec = int64(pkthdr.ts.tv_sec);
	pkt.Time.Usec = int64(pkthdr.ts.tv_usec);
	pkt.Caplen = uint32(pkthdr.caplen);
	pkt.Len = uint32(pkthdr.len);
	pkt.Data = make([]byte, pkthdr.caplen);

	for i := uint32(0) ; i < pkt.Len ; i++ {
		pkt.Data[i] = *(*byte)(unsafe.Pointer(uintptr(buf) + uintptr(i)));
	}

	return;
}
