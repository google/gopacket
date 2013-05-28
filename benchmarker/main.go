package main

import (
"io"
"bufio"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"fmt"
	"github.com/gconnell/assembly"
  "io/ioutil"
	"log"
	"os"
	"runtime/pprof"
	"strings"
	"time"
  "net/http"
)

var iface = flag.String("i", "", "")
var snaplen = flag.Int("s", 1600, "")
var count = flag.Int("c", 1000, "")
var pages = flag.Int("pages", 1000000, "")
var maxper = flag.Int("maxper", 10, "")
var flushEvery = flag.Int("flush_every", 10, "")
var flushOlderThan = flag.Int("flush_older_than", 30, "")

var zeros []byte = make([]byte, 12)

func convertTcp(ip *layers.IPDecodingLayer, t1 *layers.TCP, t2 *assembly.TCP) {
	switch ip.Version {
	case 4:
    t2.Key.Reset(ip.IPv4.SrcIP, ip.IPv4.DstIP, uint16(t1.SrcPort), uint16(t1.DstPort))
	case 6:
    t2.Key.Reset(ip.IPv6.SrcIP, ip.IPv6.DstIP, uint16(t1.SrcPort), uint16(t1.DstPort))
	default:
		panic("Invalid version")
	}
	t2.Seq = assembly.Sequence(t1.Seq)
	t2.SYN = t1.SYN
	t2.FIN = t1.FIN
	t2.RST = t1.RST
	t2.Bytes = t1.LayerPayload()
}

type benchStreamHandler struct {
  opened int
  reassembled int
  requests int
  skips int
  closes int
}
type benchReader struct {
  b *benchStreamHandler
  k assembly.Key
  c chan []assembly.Reassembly
  d chan bool
  r []assembly.Reassembly
  closed bool
}
func (b *benchStreamHandler) New(k assembly.Key) assembly.Stream {
  br := &benchReader{
    b: b,
    k: k,
    c: make(chan []assembly.Reassembly),
    d: make(chan bool),
  }
  go br.run()
  b.opened++
  return br
}
func (b *benchReader) Reassembled(r []assembly.Reassembly) {
  <-b.d
  b.c <- r
}
func (b *benchReader) run() {
  buffer := bufio.NewReader(b)
  for {
    req, err := http.ReadRequest(buffer)
    if err == nil {
      b.b.requests++
      ioutil.ReadAll(req.Body)
    } else if err == io.EOF {
      return
    }
  }
}
func (b *benchReader) Close() {
  <-b.d
  close(b.c)
  close(b.d)
  b.b.closes++
}
func (b *benchReader) stripEmpty() {
  for len(b.r) > 0 && len(b.r[0].Bytes) == 0 {
    if b.r[0].Skip {
      b.b.skips++
    }
    b.r = b.r[:len(b.r)-1]
  }
}
func (b *benchReader) Read(p []byte) (int, error) {
  var ok bool
  b.stripEmpty()
  for !b.closed && len(b.r) == 0 {
    b.d <- true
    if b.r, ok = <-b.c; ok {
      b.b.reassembled += len(b.r)
      b.stripEmpty()
    } else {
      b.closed = true
    }
  }
  if len(b.r) > 0 {
    length := copy(p, b.r[0].Bytes)
    b.r[0].Bytes = b.r[0].Bytes[length:]
    return length, nil
  }
  return 0, io.EOF
}

func main() {
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
  handler := &benchStreamHandler{}
	assembler := assembly.NewAssembler(*pages, *maxper, 10000, handler)
	success := 0
	start := time.Now()
  flushAt := time.Now().Add(time.Second * time.Duration(*flushEvery))
	var i int
	go func() {
		for {
			time.Sleep(time.Second * 3)
			duration := time.Since(start)
			log.Println("Processed", success, "of", i, "at", duration/time.Duration(success), "per packet, total", duration, "assembled", handler.reassembled, "buffered", assembler.Buffered(), "requests", handler.requests, "skips", handler.skips, "closes", handler.closes, "opened", handler.opened)
      stats, _ := handle.Stats()
      fmt.Println(stats)
		}
	}()
	for i = 0; i < *count; i++ {
    if time.Now().After(flushAt) {
      assembler.FlushOlderThan(time.Now().Add(-time.Second * time.Duration(*flushOlderThan)))
      flushAt = time.Now().Add(time.Second * time.Duration(*flushEvery))
    }
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
			assembler.Assemble(&atcp)
		default:
		}
	}
}

func min(a, b int) int {
  if a < b {
    return a
  }
  return b
}
