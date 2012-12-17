package layers

import (
	"encoding/binary"
	"github.com/gconnell/gopacket"
	"net"
	"strconv"
)

var (
	EndpointPPP = gopacket.RegisterEndpointType(0, "PPP", func([]byte) string {
		return "point"
	})
	EndpointIP = gopacket.RegisterEndpointType(1, "IP", func(b []byte) string {
		return net.IP(b).String()
	})
	EndpointMAC = gopacket.RegisterEndpointType(2, "MAC", func(b []byte) string {
		return net.HardwareAddr(b).String()
	})
	EndpointTCPPort = gopacket.RegisterEndpointType(3, "TCP", func(b []byte) string {
		return strconv.Itoa(int(binary.BigEndian.Uint16(b)))
	})
	EndpointUDPPort = gopacket.RegisterEndpointType(4, "UDP", func(b []byte) string {
		return strconv.Itoa(int(binary.BigEndian.Uint16(b)))
	})
	EndpointSCTPPort = gopacket.RegisterEndpointType(5, "SCTP", func(b []byte) string {
		return strconv.Itoa(int(binary.BigEndian.Uint16(b)))
	})
	EndpointRUDPPort = gopacket.RegisterEndpointType(6, "RUDP", func(b []byte) string {
		return strconv.Itoa(int(b[0]))
	})
)
