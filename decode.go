// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

type LayerType int

const (
	TYPE_PAYLOAD        LayerType = iota // Contains raw bytes
	TYPE_DECODE_FAILURE                  // We were unable to decode this layer
	TYPE_ETHERNET
	TYPE_IP4
	TYPE_IP6
	TYPE_TCP
	TYPE_UDP
	TYPE_ICMP
	TYPE_DOT1Q
	TYPE_ARP
)

type Layer interface {
	LayerType() LayerType
}

type Payload struct {
	Data []byte
}

func (p *Payload) LayerType() LayerType { return TYPE_PAYLOAD }
func (p *Payload) Payload() []byte      { return p.Data }

// An address

type Address interface {
	String() string
	Raw() []byte
}
type MacAddress net.HardwareAddr

func (a MacAddress) Raw() []byte    { return a }
func (a MacAddress) String() string { return net.HardwareAddr(a).String() }

type IPAddress net.IP

func (a IPAddress) Raw() []byte    { return a }
func (a IPAddress) String() string { return net.IP(a).String() }

// These layers correspond to Internet Protocol Suite (TCP/IP) layers, and their
// corresponding OSI layers, as best as possible.

type LinkLayer interface {
	Layer
	SrcLinkAddr() Address
	DstLinkAddr() Address
}
type NetworkLayer interface {
	Layer
	SrcNetAddr() Address
	DstNetAddr() Address
}
type TransportLayer interface {
	Layer
	// SrcAppAddr() Address
	// DstAppAddr() Address
}
type ApplicationLayer interface {
	Layer
	Payload() []byte
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
type decoderFunc func([]byte, *specificLayers) decodeResult

func (d decoderFunc) decode(data []byte, s *specificLayers) decodeResult {
	return d(data, s)
}

const (
	ERRBUF_SIZE = 256
)

type DecodeMethod bool

var Lazy DecodeMethod = true
var Eager DecodeMethod = false

type PacketDecoder interface {
	Decode(data []byte, lazy DecodeMethod) Packet
}

type DecodeFailure struct {
	Data  []byte
	Error error
}

func (e *DecodeFailure) Payload() []byte {
	return e.Data
}

func (e *DecodeFailure) LayerType() LayerType {
	return TYPE_DECODE_FAILURE
}

var decodeUnknown decoderFunc = func(data []byte, _ *specificLayers) (out decodeResult) {
	out.err = errors.New("Link type not currently supported")
	return
}

var decodePayload decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	payload := &Payload{Data: data}
	out.layer = payload
	s.application = payload
	return
}
