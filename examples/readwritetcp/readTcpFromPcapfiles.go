package main

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if handle, err := pcap.OpenOffline("./STP-TCN-TCAck.pcapng.cap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if StpPacket := packet.Layer(layers.LayerTypeSTP); StpPacket != nil {
				fmt.Println("This is an STP packet!")
				stp, _ := StpPacket.(*layers.STP)
				fmt.Printf("the protocol Id is %d and the root priority is %d and finally the Vlan ID is %d\n", stp.ProtocolID, stp.RouteID.Priority, stp.RouteID.SysID)
				fmt.Printf(strings.Repeat("-", 20) + "\n")
				fmt.Printf("the topologie change flag is %t and the TCA is %t\n", stp.TC, stp.TCA)
				fmt.Printf("the hello time is %d seconds, the max age is %d seconds and finally the forward delay is %d seconds\n\n", stp.HelloTime/256, stp.MaxAge/256, stp.FDelay/256)
			}
		}
	}
}
