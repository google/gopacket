package main

import (
	"bufio"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"fmt"
	"github.com/gconnell/assembly"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"time"
)

var iface = flag.String("i", "", "")
var snaplen = flag.Int("s", 1600, "")
var count = flag.Int("c", 1000, "")
var pages = flag.Int("pages", 1000000, "")
var maxper = flag.Int("maxper", 10, "")
var flushEvery = flag.Int("flush_every", 60, "")
var flushOlderThan = flag.Int("flush_older_than", 120, "")
var parseHttp = flag.Bool("http", true, "")
var threads = flag.Int("threads", 1, "")
var vlan = flag.Bool("vlan", true, "")

var zeros []byte = make([]byte, 12)

var discardBuf [4096]byte

func discardBytes(r io.Reader) {
	for {
		_, err := r.Read(discardBuf[:])
		if err == io.EOF {
			return
		}
	}
}

type benchStreamHandler struct {
	opened      int
	reassembled int
	requests    int
	skips       int
	closes      int
}

func (b *benchStreamHandler) New(_, _ gopacket.Flow) assembly.Stream {
	br := &benchReader{
		handler:      b,
		ReaderStream: assembly.NewReaderStream(false),
	}
	go br.run()
	b.opened++
	return br
}

type benchReader struct {
	assembly.ReaderStream
	handler *benchStreamHandler
}

func (b *benchReader) run() {
	if *parseHttp {
		buffer := bufio.NewReader(b)
		for {
			req, err := http.ReadRequest(buffer)
			if err == nil {
				b.handler.requests++
				ioutil.ReadAll(req.Body)
			} else if err == io.EOF {
				return
			}
		}
	} else {
		discardBytes(b)
	}
}

func thread(handle *pcap.Handle, pool *assembly.ConnectionPool, wg *sync.WaitGroup) {
	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip layers.IPDecodingLayer
	var tcp layers.TCP
	parser := gopacket.StackParser{&eth}
	if *vlan {
		parser = append(parser, &dot1q)
	}
	parser = append(parser, &ip, &tcp)
	assembler := assembly.NewAssembler(*pages, *maxper, pool)
	success := 0
	flushAt := time.Now().Add(time.Second * time.Duration(*flushEvery))
	for *count > 0 {
		*count--
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
			assembler.Assemble(ip.NetworkFlow(), &tcp)
		default:
		}
	}
	wg.Done()
}

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(*threads)

	if profile, err := os.Create("/tmp/profile"); err != nil {
		panic(err)
	} else if err := pprof.StartCPUProfile(profile); err != nil {
		panic(err)
	} else {
		defer pprof.StopCPUProfile()
	}
	fmt.Println("Opening pcap")

	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, 0)
	if err != nil {
		panic(err)
	} else if len(flag.Args()) > 0 {
		if err := handle.SetBPFFilter(strings.Join(flag.Args(), " ")); err != nil {
			panic(err)
		}
	}
	handler := &benchStreamHandler{}
	pool := assembly.NewConnectionPool(handler)
	start := time.Now()
	initial := *count
	go func() {
		for {
			time.Sleep(time.Second * 3)
			duration := time.Since(start)
			done := initial - *count
			log.Println("Processed", done, "at", duration/time.Duration(done), "per packet, total", duration, "assembled", handler.reassembled, "requests", handler.requests, "skips", handler.skips, "closes", handler.closes, "opened", handler.opened)
			stats, _ := handle.Stats()
			fmt.Println(stats)
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		thread(handle, pool, &wg)
	}
	wg.Wait()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
