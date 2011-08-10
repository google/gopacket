package main

// Parses a pcap file, writes it back to disk, then verifies the files
// are the same.
import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"pcap"
)

var input *string = flag.String("input", "", "input file")
var output *string = flag.String("output", "", "output file")
var decode *bool = flag.Bool("decode", false, "print decoded packets")

func copyPcap(dest, src string) {
	f, err := os.Open(src)
	if err != nil {
		fmt.Printf("couldn't open %q: %v", src, err)
		return
	}
	reader, err := pcap.NewReader(bufio.NewReader(f))
	if err != nil {
		fmt.Printf("couldn't create reader: %v", err)
		return
	}
	w, err := os.Create(dest)
	if err != nil {
		fmt.Printf("couldn't open %q: %v", dest, err)
		return
	}
	buf := bufio.NewWriter(w)
	writer, err := pcap.NewWriter(buf, &reader.Header)
	if err != nil {
		fmt.Printf("couldn't create writer: %v", err)
		return
	}
	for {
		pkt := reader.Next()
		if pkt == nil {
			break
		}
		if *decode {
			pkt.Decode()
			fmt.Println(pkt.String())
		}
		writer.Write(pkt)
	}
	buf.Flush()
	w.Close()
}

func check(dest, src string) {
	f, err := os.Open(src)
	defer f.Close()
	if err != nil {
		fmt.Printf("couldn't open %q: %v", src, err)
		return
	}
	freader := bufio.NewReader(f)

	g, err := os.Open(dest)
	defer g.Close()
	if err != nil {
		fmt.Printf("couldn't open %q: %v", src, err)
		return
	}
	greader := bufio.NewReader(g)

	for {
		fb, ferr := freader.ReadByte()
		gb, gerr := greader.ReadByte()

		if ferr == os.EOF && gerr == os.EOF {
			break
		}
		if fb == gb {
			continue
		}
		fmt.Println("FAIL")
		return
	}

	fmt.Println("PASS")
}

func main() {
	flag.Parse()

	copyPcap(*output, *input)
	check(*output, *input)
}
