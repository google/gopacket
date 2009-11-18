package main

import (
	"pcap";
	"fmt";
	"flag";
	"time";
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
		fmt.Printf("time: %d.%06d (%s) caplen: %d len: %d\nData:", 
				int64(pkt.Time.Sec), int64(pkt.Time.Usec), 
				time.SecondsToLocalTime(int64(pkt.Time.Sec)).Asctime(), int64(pkt.Caplen), int64(pkt.Len));
		for i:=uint32(0) ; i<pkt.Caplen ; i++ {
			if i % 32 == 0 {
				fmt.Printf("\n")
			}
			if 32 <= pkt.Data[i] && pkt.Data[i] <= 126 {
				fmt.Printf("%c", pkt.Data[i]);
			} else {
				fmt.Printf(".");
			}
		}
		fmt.Printf("\n\n");
	}

}
