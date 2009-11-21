package main

import (
	"pcap";
	"fmt";
	"flag";
	"time";
	"os";
)

const (
	TYPE_IP = 0x0800;
	TYPE_ARP = 0x0806;
	TYPE_IP6 = 0x86DD;

	IP_ICMP = 1;
	IP_INIP = 4;
	IP_TCP = 6;
	IP_UDP = 17;

)

func main() {
	var device *string = flag.String("i", "", "interface");
	var snaplen *int = flag.Int("s", 65535, "snaplen");
	expr := "";

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [ -d device ] [ -s snaplen ] [ expression ]\n", os.Args[0]);
		os.Exit(1);
	};

	flag.Parse();

	if (len(flag.Args()) > 0) {
		expr = flag.Arg(0);
	}

	if *device == "" {
		flag.Usage();
	}

	h, err := pcap.Openlive(*device, int32(*snaplen), true, 0);
	if h == nil {
		fmt.Fprintf(os.Stderr, "tcpdump: %s\n", err);
		return
	}

	if expr != "" {
		ferr := h.Setfilter(expr);
		if ferr != "" {
			fmt.Printf("tcpdump: %s\n", ferr);
		}
	}

	for pkt := h.Next() ; pkt != nil ; pkt = h.Next() {
		Printpacket(pkt);
	}

}


func Printpacket(pkt *pcap.Packet) {
	//destmac := Decodemac(pkt.Data[0:6]);
	//srcmac := Decodemac(pkt.Data[6:12]);
	pkttype := Decodeuint16(pkt.Data[12:14]);

	t := time.SecondsToLocalTime(int64(pkt.Time.Sec));
	fmt.Printf("%d:%d:%d.%06d ", t.Hour, t.Minute, t.Second, pkt.Time.Usec);

	//fmt.Printf("%012x -> %012x ", srcmac, destmac);

	switch (pkttype) {
		case TYPE_IP: Decodeip(pkt.Data[14:])
		case TYPE_ARP: Decodearp(pkt.Data[14:])
		default: Unsupported(pkttype)
	}

	fmt.Printf("\n");
}

func Decodemac(pkt []byte) uint64 {
	mac := uint64(0);
	for i:= uint(0) ; i < 6 ; i++ {
		mac = (mac << 8) + uint64(pkt[i]);
	}
	return mac
}

func Decodeuint16(pkt []byte) uint16 {
	return uint16(pkt[0]) << 8 + uint16(pkt[1])
}

func Decodeuint32(pkt []byte) uint32 {
	return uint32(pkt[0]) << 24 + uint32(pkt[1]) << 16 + uint32(pkt[2]) << 8 + uint32(pkt[3])
}

func Unsupported(pkttype uint16) {
	fmt.Printf("unsupported protocol %d", int(pkttype));
}

func Decodearp(pkt []byte) {
	fmt.Printf("ARP: TODO");
}

type Iphdr struct {
	Version uint8;
	Ihl uint8;
	Tos uint8;
	Length uint16;
	Id uint16;
	Flags uint8;
	FragOffset uint16;
	Ttl uint8;
	Protocol uint8;
	Checksum uint16;
	SrcIp []byte;
	DestIp []byte;
}

func Decodeip(pkt []byte) {
	ip := new(Iphdr);

	ip.Version = uint8(pkt[0]) >> 4;
	ip.Ihl = uint8(pkt[0]) & 0x0F;;
	ip.Tos = pkt[1];
	ip.Length = Decodeuint16(pkt[2:4]);
	ip.Id = Decodeuint16(pkt[4:6]);
	flagsfrags := Decodeuint16(pkt[6:8]);
	ip.Flags = uint8(flagsfrags >> 13);
	ip.FragOffset = flagsfrags & 0x1FFF;
	ip.Ttl = pkt[8];
	ip.Protocol = pkt[9];
	ip.Checksum = Decodeuint16(pkt[10:12]);
	ip.SrcIp = pkt[12:16];
	ip.DestIp = pkt[16:20];

	switch (ip.Protocol) {
		case IP_TCP: Decodetcp(ip, pkt[ip.Ihl*4:])
		case IP_UDP: Decodeudp(ip, pkt[ip.Ihl*4:])
		case IP_ICMP: Decodeicmp(ip, pkt[ip.Ihl*4:])
		case IP_INIP:
			Printip(ip.SrcIp);
			fmt.Printf(" > ");
			Printip(ip.DestIp);
			fmt.Printf(" IP in IP: ");
			Decodeip(pkt[ip.Ihl*4:]);
		default:
			Printip(ip.SrcIp);
			fmt.Printf(" > ");
			Printip(ip.DestIp);
			fmt.Printf(" unsupported protocol %d", int(ip.Protocol));
	}
}

type Tcphdr struct {
	SrcPort uint16;
	DestPort uint16;
	Seq uint32;
	Ack uint32;
}

func Decodetcp(ip *Iphdr, pkt []byte) {
	tcp := new(Tcphdr);
	tcp.SrcPort = Decodeuint16(pkt[0:2]);
	tcp.DestPort = Decodeuint16(pkt[2:4]);
	tcp.Seq = Decodeuint32(pkt[4:8]);
	tcp.Ack = Decodeuint32(pkt[8:12]);

	Printtcp(ip, tcp);
}

func Printtcp(ip *Iphdr, tcp *Tcphdr) {
	fmt.Printf("TCP ");
	Printip(ip.SrcIp);
	fmt.Printf(":%d > ", int(tcp.SrcPort));
	Printip(ip.DestIp);
	fmt.Printf(":%d SEQ=%d ACK=%d", int(tcp.DestPort), int64(tcp.Seq), int64(tcp.Ack));
}

func Printip(ip []byte) {
	for i:=0;i<4;i++ {
		fmt.Printf("%d", int(ip[i]));
		if i < 3 {
			fmt.Printf(".");
		}
	}
}

type Udphdr struct {
	SrcPort uint16;
	DestPort uint16;
	Length uint16;
	Checksum uint16;
}

func Decodeudp(ip *Iphdr, pkt []byte) {
	udp := new(Udphdr);
	udp.SrcPort = Decodeuint16(pkt[0:2]);
	udp.DestPort = Decodeuint16(pkt[2:4]);
	udp.Length = Decodeuint16(pkt[4:6]);
	udp.Checksum = Decodeuint16(pkt[6:8]);

	fmt.Printf("UDP ");
	Printip(ip.SrcIp);
	fmt.Printf(":%d > ", udp.SrcPort);
	Printip(ip.DestIp);
	fmt.Printf(":%d LEN=%d CHKSUM=%d", int(udp.DestPort), int(udp.Length), int(udp.Checksum));
}

func Decodeicmp(ip *Iphdr, pkt []byte) {
	fmt.Printf("TODO: ICMP")
}
