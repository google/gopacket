package main

import (
	"pcap";
	"fmt";
	"flag";
)

func min(x uint32, y uint32) uint32 {
	if x < y {
		return x;
	}
	return y;
}

func main() {
	var device *string = flag.String("d", "", "device");
	var file *string = flag.String("r", "", "file");

	flag.Parse();
	
	var h *pcap.Pcap;
	var err string;

	if *device != "" {
		h, err = pcap.Openlive(*device, 65535, true, 0);
		if h == nil {
			fmt.Printf("Openlive(%s) failed: %s\n", *device, err);
			return
		}
	} else if *file != "" {
		h, err = pcap.Openoffline(*file);
		if h == nil {
			fmt.Printf("Openoffline(%s) failed: %s\n", *file, err);
			return
		}
	} else {
		fmt.Printf("usage: pcaptest [-d <device> | -r <file>]\n");
		return
	}

	for pkt := h.Next() ; pkt != nil ; pkt = h.Next() {
		fmt.Printf("time: %u.%06u caplen: %u len: %u\n\tData:\n", uint(pkt.Time.Sec), uint(pkt.Time.Usec), uint(pkt.Caplen), uint(pkt.Len));
		for i:=uint32(0) ; i<pkt.Caplen ; i++ {
			if 32 <= pkt.Data[i] && pkt.Data[i] <= 126 {
				fmt.Printf("%c", pkt.Data[i]);
			} else {
				fmt.Printf(".");
			}
		}
		fmt.Printf("\n");
	}

}
