// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"net"
	"strconv"
)

// LayerType is a unique identifier for each type of layer.  This enumeration
// does not match with any externally available numbering scheme... it's solely
// usable/useful within this library as a means for requesting layer types
// (see Packet.Layer) and determining which types of layers have been decoded.
// A LayerType corresponds 1:1 to a struct type.
type LayerType int

const (
	LayerTypePayload LayerType = iota
	LayerTypeDecodeFailure
	LayerTypeEthernet
	LayerTypePPP
	LayerTypeIPv4
	LayerTypeIPv6
	LayerTypeTCP
	LayerTypeUDP
	LayerTypeICMP
	LayerTypeDot1Q
	LayerTypeARP
	LayerTypeMPLS
)

func (l LayerType) String() string {
	switch l {
	case LayerTypePayload:
		return "Payload"
	case LayerTypeDecodeFailure:
		return "DecodeFailure"
	case LayerTypeEthernet:
		return "Ethernet"
	case LayerTypePPP:
		return "PPP"
	case LayerTypeIPv4:
		return "IPv4"
	case LayerTypeIPv6:
		return "IPv6"
	case LayerTypeTCP:
		return "TCP"
	case LayerTypeUDP:
		return "UDP"
	case LayerTypeICMP:
		return "ICMP"
	case LayerTypeDot1Q:
		return "Dot1Q"
	case LayerTypeARP:
		return "ARP"
	}
	return strconv.Itoa(int(l))
}

// Layer represents a single decoded packet layer (using either the
// OSI or TCP/IP definition of a layer).  When decoding, a packet's data is
// broken up into a number of layers.  The caller may call LayerType() to
// figure out which type of layer he's received from the packet.  Optionally,
// he may then use a type assertion to get the actual layer type for deep
// inspection of the data.
type Layer interface {
	LayerType() LayerType
}

// Payload is a Layer containing the payload of a packet.  The definition of
// what constitutes the payload of a packet depends on previous layers; for
// TCP and UDP, we stop decoding above layer 4 and return the remaining
// bytes as a Payload.  Payload is an ApplicationLayer.
type Payload struct {
	Data []byte
}

// LayerType returns LayerTypePayload
func (p *Payload) LayerType() LayerType { return LayerTypePayload }
func (p *Payload) Payload() []byte      { return p.Data }

// Endpoint is the set of bytes used to address packets at various layers.
// See LinkLayer, NetworkLayer, and TransportLayer specifications.
type Endpoint struct {
	typ LayerType
	raw string
}

func (e Endpoint) LayerType() LayerType { return e.typ }
func (e Endpoint) Raw() []byte          { return []byte(e.raw) }
func EndpointFromIP(a net.IP) (_ Endpoint, err error) {
	if len(a) == 4 {
		return Endpoint{LayerTypeIPv4, string(a)}, nil
	} else if len(a) == 16 {
		return Endpoint{LayerTypeIPv6, string(a)}, nil
	}
	return nil, fmt.Errorf("Invalid IP byte string has size %d", len(a))
}

type Flow struct {
	typ      LayerType
	src, dst string
}

func NewFlow(src, dst Endpoint) (_ Flow, err error) {
	if src.Type != dst.Type {
		err = fmt.Errorf("Mismatched endpoint types: %s->%s", src.Type, dst.Type)
		return
	}
	return Flow{src.typ, src.raw, dst.raw}
}
func (f Flow) Endpoints() (src, dst Endpoint) {
	return Endpoint{f.typ, f.src}, Endpoint{f.typ, f.dst}
}

func (a Endpoint) String() string {
	switch a.Type {
	case LayerTypeIPv4:
		fallthrough
	case LayerTypeIPv6:
		return net.IP([]byte(a.Raw)).String()
	case LayerTypeEthernet:
		return net.HardwareAddr([]byte(a.Raw)).String()
	case LayerTypeTCP:
		return strconv.Itoa(int(binary.BigEndian.Uint16([]byte(a.Raw))))
	case LayerTypePPP:
		return "point"
	}
	return "endpoint"
}

// These layers correspond to Internet Protocol Suite (TCP/IP) layers, and their
// corresponding OSI layers, as best as possible.

// LinkLayer is the packet layer corresponding to TCP/IP layer 1 (OSI layer 2)
type LinkLayer interface {
	Layer
	LinkFlow() Flow
}

// NetworkLayer is the packet layer corresponding to TCP/IP layer 2 (OSI
// layer 3)
type NetworkLayer interface {
	Layer
	NetFlow() Flow
}

// TransportLayer is the packet layer corresponding to the TCP/IP layer 3 (OSI
// layer 4)
type TransportLayer interface {
	Layer
	AppFlow() Flow
}

// ApplicationLayer is the packet layer corresponding to the TCP/IP layer 4 (OSI
// layer 7), also known as the packet payload.
type ApplicationLayer interface {
	Layer
	Payload() []byte
}

// ErrorLayer is a packet layer created when decoding of the packet has failed.
// Its payload is all the bytes that we were unable to decode, and the returned
// error details why the decoding failed.
type ErrorLayer interface {
	Layer
	Payload() []byte
	Error() error
}
