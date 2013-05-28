package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/gconnell/assembly"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"
)

var iface = flag.String("i", "", "")
var snaplen = flag.Int("s", 1600, "")
var count = flag.Int("c", 1000, "")

func convertTcp(ip *layers.IPDecodingLayer, t1 *layers.TCP, t2 *assembly.TCP) {
	switch ip.Version {
	case 4:
		t2.Key[0] = 4
		copy(t2.Key[1:], ip.IPv4.SrcIP)
		copy(t2.Key[17:], ip.IPv4.DstIP)
	case 6:
		t2.Key[0] = 6
		copy(t2.Key[1:], ip.IPv6.SrcIP)
		copy(t2.Key[17:], ip.IPv6.DstIP)
	default:
		panic("Invalid version")
	}
	binary.BigEndian.PutUint16(t2.Key[33:], uint16(t1.SrcPort))
	binary.BigEndian.PutUint16(t2.Key[35:], uint16(t1.DstPort))
	t2.Seq = assembly.Sequence(t1.Seq)
	t2.SYN = t1.SYN
	t2.FIN = t1.FIN
	t2.RST = t1.RST
	t2.Bytes = t1.LayerPayload()
}

func main() {
	runtime.GOMAXPROCS(4)
	flag.Parse()

	if profile, err := os.Create("/tmp/profile"); err != nil {
		panic(err)
	} else if err := pprof.StartCPUProfile(profile); err != nil {
		panic(err)
	} else {
		defer pprof.StopCPUProfile()
	}

	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, 0)
	if err != nil {
		panic(err)
	} else if len(flag.Args()) > 0 {
		if err := handle.SetBPFFilter(strings.Join(flag.Args(), " ")); err != nil {
			panic(err)
		}
	}
	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip layers.IPDecodingLayer
	var tcp layers.TCP
	var atcp assembly.TCP
	parser := gopacket.StackParser{
		&eth,
		&dot1q,
		&ip,
		&tcp,
	}
	assembler := assembly.NewAssembler(2000000, 10, 10000)
	success := 0
	assembled := 0
	start := time.Now()
	var i int
	go func() {
		for {
			time.Sleep(time.Second * 3)
			duration := time.Since(start)
			log.Println("Processed", success, "of", i, "at", duration/time.Duration(success), "per packet, total", duration, "assembled", assembled, "buffered", assembler.Buffered())
		}
	}()
	for i = 0; i < *count; i++ {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			fmt.Println("Error: ", err)
			continue
		}
		n, _, err := parser.DecodeBytes(data, gopacket.NilDecodeFeedback, gopacket.HandlePanic)
		switch n {
		case 4:
			success++
			convertTcp(&ip, &tcp, &atcp)
			assembled += len(assembler.Assemble(&atcp))
		default:
		}
	}
	stats, err := handle.Stats()
	fmt.Println(stats)
}
