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

func NewIPEndpoint(a net.IP) gopacket.Endpoint {
	return gopacket.NewEndpoint(EndpointIP, []byte(a))
}
func NewMACEndpoint(a net.HardwareAddr) gopacket.Endpoint {
	return gopacket.NewEndpoint(EndpointMAC, []byte(a))
}
func newPortEndpoint(t gopacket.EndpointType, p uint16) gopacket.Endpoint {
	return gopacket.NewEndpoint(t, []byte{byte(p >> 16), byte(p)})
}
func NewTCPPortEndpoint(p uint16) gopacket.Endpoint {
	return newPortEndpoint(EndpointTCPPort, p)
}
func NewUDPPortEndpoint(p uint16) gopacket.Endpoint {
	return newPortEndpoint(EndpointUDPPort, p)
}
func NewSCTPPortEndpoint(p uint16) gopacket.Endpoint {
	return newPortEndpoint(EndpointSCTPPort, p)
}
func NewRUDPPortEndpoint(p uint8) gopacket.Endpoint {
	return gopacket.NewEndpoint(EndpointRUDPPort, []byte{p})
}
