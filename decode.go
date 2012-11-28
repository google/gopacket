// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"errors"
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
	TYPE_PAYLOAD        LayerType = iota // Type: Payload
	TYPE_DECODE_FAILURE                  // Type: DecodeFailure
	TYPE_ETHERNET                        // Type: Ethernet
	TYPE_PPP                             // Type: PPP
	TYPE_IP4                             // Type: IPv4
	TYPE_IP6                             // Type: IPv6
	TYPE_TCP                             // Type: TCP
	TYPE_UDP                             // Type: UDP
	TYPE_ICMP                            // Type: ICMP
	TYPE_DOT1Q                           // Type: Dot1Q
	TYPE_ARP                             // Type: ARP
)

func (l LayerType) String() string {
	switch l {
	case TYPE_PAYLOAD:
		return "Payload"
	case TYPE_DECODE_FAILURE:
		return "DecodeFailure"
	case TYPE_ETHERNET:
		return "Ethernet"
	case TYPE_PPP:
		return "PPP"
	case TYPE_IP4:
		return "IPv4"
	case TYPE_IP6:
		return "IPv6"
	case TYPE_TCP:
		return "TCP"
	case TYPE_UDP:
		return "UDP"
	case TYPE_ICMP:
		return "ICMP"
	case TYPE_DOT1Q:
		return "Dot1Q"
	case TYPE_ARP:
		return "ARP"
	}
	return "<Unknown>"
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

// Returns TYPE_PAYLOAD
func (p *Payload) LayerType() LayerType { return TYPE_PAYLOAD }
func (p *Payload) Payload() []byte      { return p.Data }

// Address is the set of bytes used to address packets at various layers.
// See LinkLayer, NetworkLayer, and TransportLayer specifications.
type Address interface {
	String() string
	Raw() []byte
}

// MacAddress is the set of bytes representing a MAC address
type MacAddress net.HardwareAddr

func (a MacAddress) Raw() []byte    { return a }
func (a MacAddress) String() string { return net.HardwareAddr(a).String() }

// IPAddress is the set of bytes representing an IPv4 or IPv6 address
type IPAddress net.IP

func (a IPAddress) Raw() []byte    { return a }
func (a IPAddress) String() string { return net.IP(a).String() }

// PortAddress is the set of bytes representing a port number.  Users may
// get the port number for TCP/UDP layers by requesting it directly from the
// TCP or UDP layer (SrcPort/DstPort), but this address allows us to treat
// the port as a protocol-agnostic address for an application on a system.
type PortAddress []byte

func (a PortAddress) Raw() []byte    { return a }
func (a PortAddress) String() string { return strconv.Itoa(int(binary.BigEndian.Uint16(a))) }

// These layers correspond to Internet Protocol Suite (TCP/IP) layers, and their
// corresponding OSI layers, as best as possible.

// LinkLayer is the packet layer corresponding to TCP/IP layer 1 (OSI layer 2)
type LinkLayer interface {
	Layer
	SrcLinkAddr() Address
	DstLinkAddr() Address
}

// NetworkLayer is the packet layer corresponding to TCP/IP layer 2 (OSI
// layer 3)
type NetworkLayer interface {
	Layer
	SrcNetAddr() Address
	DstNetAddr() Address
}

// TransportLayer is the packet layer corresponding to the TCP/IP layer 3 (OSI
// layer 4)
type TransportLayer interface {
	Layer
	SrcAppAddr() Address
	DstAppAddr() Address
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

type decodeResult struct {
	// An error encountered in this decode call.  If this is set, everything else
	// will be ignored.
	err error
	// The layer we've created with this decode call
	layer Layer
	// The next decoder to call
	next decoder
	// The bytes that are left to be decoded
	left []byte
}

// decoder decodes the next layer in a packet.  It returns a set of useful
// information, which is used by the packet decoding logic to update packet
// state.  Optionally, the decode function may set any of the specificLayer
// pointers to point to the new layer it has created.
type decoder interface {
	decode([]byte, *specificLayers) decodeResult
}

// decoderFunc is an implementation of decoder that's a simple function.
type decoderFunc func([]byte, *specificLayers) decodeResult

func (d decoderFunc) decode(data []byte, s *specificLayers) decodeResult {
	return d(data, s)
}

// DecodeMethod tells gopacket how to decode a packet.
type DecodeMethod bool

const (
	// Lazy decoding decodes the minimum number of layers needed to return data
	// for a packet at each function call.  Be careful using this with concurrent
	// packet processors, as each call to packet.* could mutate the packet, and
	// two concurrent function calls could interact poorly.
	Lazy DecodeMethod = true
	// Eager decoding decodes all layers of a packet immediately.  Slower than
	// lazy decoding, but better if the packet is expected to be used concurrently
	// at a later date, since after an eager Decode, the packet is guaranteed to
	// not mutate itself on packet.* function calls.
	Eager DecodeMethod = false
)

// PacketDecoder provides the functionality to decode a set of bytes into a
// packet, and decode that packet into one or more layers.
type PacketDecoder interface {
	Decode(data []byte, lazy DecodeMethod) Packet
}

// DecodeFailure is a packet layer created if decoding of the packet data failed
// for some reason.  It implements ErrorLayer.
type DecodeFailure struct {
	data []byte
	err  error
}

func (d *DecodeFailure) Payload() []byte { return d.data }
func (d *DecodeFailure) Error() error    { return d.err }

// Returns TYPE_DECODE_FAILURE
func (d *DecodeFailure) LayerType() LayerType { return TYPE_DECODE_FAILURE }

// decodeUnknown "decodes" unsupported data types by returning an error.
var decodeUnknown decoderFunc = func(data []byte, _ *specificLayers) (out decodeResult) {
	out.err = errors.New("Link type not currently supported")
	return
}

// decodePayload decodes data by returning it all in a Payload layer.
var decodePayload decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	payload := &Payload{Data: data}
	out.layer = payload
	s.application = payload
	return
}

// FlowKey is a hashable struct that associates a packet with its unique
// flow.
type FlowKey struct {
	netType, transType             LayerType
	srcNet, dstNet, srcApp, dstApp string
}

// NewFlowKey creates a new FlowKey from a Network and Transport layer,
// guaranteed to succeed.
func NewFlowKey(net NetworkLayer, trans TransportLayer) FlowKey {
	return FlowKey{
		netType:   net.LayerType(),
		transType: trans.LayerType(),
		srcNet:    string(net.SrcNetAddr().Raw()),
		dstNet:    string(net.DstNetAddr().Raw()),
		srcApp:    string(trans.SrcAppAddr().Raw()),
		dstApp:    string(trans.DstAppAddr().Raw()),
	}
}
