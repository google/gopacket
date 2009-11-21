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
	fmt.Printf("%02d:%02d:%02d.%06d ", t.Hour, t.Minute, t.Second, pkt.Time.Usec);

	//fmt.Printf("%012x -> %012x ", srcmac, destmac);

	switch pkttype {
		case TYPE_IP: Decodeip(pkt.Data[14:])
		case TYPE_ARP: Decodearp(pkt.Data[14:])
		case TYPE_IP6: Decodeip6(pkt.Data[14:]);
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

type Arphdr struct {
	Addrtype uint16;
	Protocol uint16;
	HwAddressSize uint8;
	ProtAddressSize uint8;
	Operation uint16;
	SourceHwAddress []byte;
	SourceProtAddress []byte;
	DestHwAddress []byte;
	DestProtAddress []byte;
}

func Arpop(op uint16) string {
	switch op {
		case 1: return "Request"
		case 2: return "Reply"
	}
	return ""
}

func Decodearp(pkt []byte) {
	arp := new(Arphdr);
	arp.Addrtype = Decodeuint16(pkt[0:2]);
	arp.Protocol = Decodeuint16(pkt[2:4]);
	arp.HwAddressSize = pkt[4];
	arp.ProtAddressSize = pkt[5];
	arp.Operation = Decodeuint16(pkt[6:8]);
	arp.SourceHwAddress = pkt[8:8+arp.HwAddressSize];
	arp.SourceProtAddress = pkt[8+arp.HwAddressSize:8+arp.HwAddressSize+arp.ProtAddressSize];
	arp.DestHwAddress = pkt[8+arp.HwAddressSize+arp.ProtAddressSize:8+2*arp.HwAddressSize+arp.ProtAddressSize];
	arp.DestProtAddress = pkt[8+2*arp.HwAddressSize+arp.ProtAddressSize:8+2*arp.HwAddressSize+2*arp.ProtAddressSize];

	fmt.Printf("ARP %s ", Arpop(arp.Operation));

	if arp.Addrtype == pcap.LINKTYPE_ETHERNET && arp.Protocol == TYPE_IP {
		fmt.Printf("%012x (", Decodemac(arp.SourceHwAddress));
		Printip(arp.SourceProtAddress);
		fmt.Printf(") > %012x (", Decodemac(arp.DestHwAddress));
		Printip(arp.DestProtAddress);
		fmt.Printf(")")
	} else {
		fmt.Printf("addrtype = %d protocol = %d", arp.Addrtype, arp.Protocol)
	}
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

	switch ip.Protocol {
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
	DataOffset uint8;
	Flags uint8;
	Window uint16;
	Checksum uint16;
	Urgent uint16;
	Data []byte;
}

const (
	TCP_FIN = 1 << iota;
	TCP_SYN;
	TCP_RST;
	TCP_PSH;
	TCP_ACK;
	TCP_URG;
)

func Decodetcp(ip *Iphdr, pkt []byte) {
	tcp := new(Tcphdr);
	tcp.SrcPort = Decodeuint16(pkt[0:2]);
	tcp.DestPort = Decodeuint16(pkt[2:4]);
	tcp.Seq = Decodeuint32(pkt[4:8]);
	tcp.Ack = Decodeuint32(pkt[8:12]);
	tcp.DataOffset = pkt[12] & 0x0F;
	tcp.Flags = uint8(Decodeuint16(pkt[12:14]) & 0x3F);
	tcp.Window = Decodeuint16(pkt[14:16]);
	tcp.Checksum = Decodeuint16(pkt[16:18]);
	tcp.Urgent = Decodeuint16(pkt[18:20]);
	tcp.Data = pkt[tcp.DataOffset*4:];

	Printtcp(ip, tcp);
}

func Printtcp(ip *Iphdr, tcp *Tcphdr) {
	fmt.Printf("TCP ");
	Printip(ip.SrcIp);
	fmt.Printf(":%d > ", int(tcp.SrcPort));
	Printip(ip.DestIp);
	fmt.Printf(":%d ", int(tcp.DestPort));
	Printflags(tcp.Flags);
	fmt.Printf(" SEQ=%d ACK=%d", int64(tcp.Seq), int64(tcp.Ack))
}

func Printflags(flags uint8) {
	fmt.Printf("[ ");
	if 0 != (flags & TCP_SYN) {
		fmt.Printf("syn ")
	}
	if 0 != (flags & TCP_FIN) {
		fmt.Printf("fin ")
	}
	if 0 != (flags & TCP_ACK) {
		fmt.Printf("ack ")
	}
	if 0 != (flags & TCP_PSH) {
		fmt.Printf("psh ")
	}
	if 0 != (flags & TCP_RST) {
		fmt.Printf("rst ")
	}
	if 0 != (flags & TCP_URG) {
		fmt.Printf("urg ")
	}
	fmt.Printf("]")
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

type Icmphdr struct {
	Type uint8;
	Code uint8;
	Checksum uint16;
	Id uint16;
	Seq uint16;
	Data []byte;
}

func Decodeicmp(ip *Iphdr, pkt []byte) {
	icmp := new(Icmphdr);
	icmp.Type = pkt[0];
	icmp.Code = pkt[1];
	icmp.Checksum = Decodeuint16(pkt[2:4]);
	icmp.Id = Decodeuint16(pkt[4:6]);
	icmp.Seq = Decodeuint16(pkt[6:8]);
	icmp.Data = pkt[8:];

	Printicmp(ip, icmp);
}

func Printicmp(ip *Iphdr, icmp *Icmphdr) {
	fmt.Printf("ICMP ");
	Printip(ip.SrcIp);
	fmt.Printf(" > ");
	Printip(ip.DestIp);
	fmt.Printf(" Type = %d Code = %d ", icmp.Type, icmp.Code);
	switch icmp.Type {
		case 0: fmt.Printf("Echo reply ttl=%d seq=%d", ip.Ttl, icmp.Seq)
		case 3:
			switch icmp.Code {
				case 0: fmt.Printf("Network unreachable")
				case 1: fmt.Printf("Host unreachable")
				case 2: fmt.Printf("Protocol unreachable")
				case 3: fmt.Printf("Port unreachable")
				default: fmt.Printf("Destination unreachable")
			}
		case 8: fmt.Printf("Echo request ttl=%d seq=%d", ip.Ttl, icmp.Seq)
		case 30: fmt.Printf("Traceroute")
	}
}

func Decodeip6(pkt []byte) {
	fmt.Printf("TODO: IPv6")
}
