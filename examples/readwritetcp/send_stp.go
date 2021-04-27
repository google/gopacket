package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device  string = "wlp7s0"
	snaplen int32  = 65535
	promisc bool   = false
	err     error
	handle  *pcap.Handle
)

func main() {
	handle, err = pcap.OpenLive(device, snaplen, promisc, pcap.BlockForever)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		return
	}
	defer handle.Close()

	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeLLC,
		SrcMAC:       net.HardwareAddr{0x64, 0x5a, 0x04, 0xaf, 0x33, 0xdc},
		DstMAC:       net.HardwareAddr{0x08, 0x00, 0x27, 0x7e, 0xd0, 0x2f},
		Length:       38,
	}

	llc := layers.LLC{
		DSAP:    66,
		SSAP:    66,
		IG:      false,
		CR:      false,
		Control: 3,
	}

	stp := layers.STP{
		ProtocolID: 0,
		Version:    0,
		Type:       0,
		RouteID: layers.STPSwitchID{
			Priority: 32768,
			SysID:    1,
			HwAddr:   net.HardwareAddr{0x64, 0x5a, 0x04, 0xaf, 0x33, 0xdc},
		},
		Cost: 0,
		BridgeID: layers.STPSwitchID{
			Priority: 32768,
			SysID:    1,
			HwAddr:   net.HardwareAddr{0x64, 0x5a, 0x04, 0xaf, 0x33, 0xdc},
		},
		PortID:     0x8001,
		MessageAge: 0,
		MaxAge:     20 * 256,
		HelloTime:  2 * 256,
		FDelay:     15 * 256,
	}
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	buffer := gopacket.NewSerializeBuffer()

	if err = gopacket.SerializeLayers(buffer, options,
		&eth,
		&llc,
		&stp,
		//gopacket.Payload(payload),
	); err != nil {
		fmt.Printf("[-] Serialize error: %s\n", err.Error())
		return
	}
	outgoingPacket := buffer.Bytes()

	if err = handle.WritePacketData(outgoingPacket); err != nil {
		fmt.Printf("[-] Error while sending: %s\n", err.Error())
		return
	}

}
