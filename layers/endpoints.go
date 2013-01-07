// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"github.com/gconnell/gopacket"
	"net"
	"strconv"
)

var (
	EndpointPPP = gopacket.RegisterEndpointType(0, gopacket.EndpointTypeMetadata{"PPP", func([]byte) string {
		return "point"
	}})
	EndpointIP = gopacket.RegisterEndpointType(1, gopacket.EndpointTypeMetadata{"IP", func(b []byte) string {
		return net.IP(b).String()
	}})
	EndpointMAC = gopacket.RegisterEndpointType(2, gopacket.EndpointTypeMetadata{"MAC", func(b []byte) string {
		return net.HardwareAddr(b).String()
	}})
	EndpointTCPPort = gopacket.RegisterEndpointType(3, gopacket.EndpointTypeMetadata{"TCP", func(b []byte) string {
		return strconv.Itoa(int(binary.BigEndian.Uint16(b)))
	}})
	EndpointUDPPort = gopacket.RegisterEndpointType(4, gopacket.EndpointTypeMetadata{"UDP", func(b []byte) string {
		return strconv.Itoa(int(binary.BigEndian.Uint16(b)))
	}})
	EndpointSCTPPort = gopacket.RegisterEndpointType(5, gopacket.EndpointTypeMetadata{"SCTP", func(b []byte) string {
		return strconv.Itoa(int(binary.BigEndian.Uint16(b)))
	}})
	EndpointRUDPPort = gopacket.RegisterEndpointType(6, gopacket.EndpointTypeMetadata{"RUDP", func(b []byte) string {
		return strconv.Itoa(int(b[0]))
	}})
	EndpointUDPLitePort = gopacket.RegisterEndpointType(7, gopacket.EndpointTypeMetadata{"UDPLite", func(b []byte) string {
		return strconv.Itoa(int(binary.BigEndian.Uint16(b)))
	}})
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
func NewTCPPortEndpoint(p TCPPort) gopacket.Endpoint {
	return newPortEndpoint(EndpointTCPPort, uint16(p))
}
func NewUDPPortEndpoint(p UDPPort) gopacket.Endpoint {
	return newPortEndpoint(EndpointUDPPort, uint16(p))
}
func NewSCTPPortEndpoint(p SCTPPort) gopacket.Endpoint {
	return newPortEndpoint(EndpointSCTPPort, uint16(p))
}
func NewRUDPPortEndpoint(p RUDPPort) gopacket.Endpoint {
	return gopacket.NewEndpoint(EndpointRUDPPort, []byte{byte(p)})
}
func NewUDPLitePortEndpoint(p UDPLitePort) gopacket.Endpoint {
	return newPortEndpoint(EndpointUDPLitePort, uint16(p))
}
