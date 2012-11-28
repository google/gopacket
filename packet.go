// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"errors"
	"fmt"
	"strings"
)

// Packet is the primary object used by gopacket.  Packets are created by a
// PacketDecoder's Decode call.  A packet is made up of a set of Data(), which
// is broken into a number of Layers as it is decoded.
type Packet interface {
	// Returns all data associated with this packet
	Data() []byte
	// Returns all layers in this packet, computing them as necessary
	Layers() []Layer
	// Returns the first layer in this packet of the given type, or nil
	Layer(LayerType) Layer
	// Printable
	String() string

	// Accessors to specific commonly-available layers, return nil if the layer
	// doesn't exist or hasn't been computed yet.
	LinkLayer() LinkLayer               // Returns the link layer
	NetworkLayer() NetworkLayer         // Returns the network layer
	TransportLayer() TransportLayer     // Returns the transport layer
	ApplicationLayer() ApplicationLayer // Returns the application layer
	// ErrorLayer is particularly useful, since it returns nil if the packet
	// was fully decoded successfully, and non-nil if an error was encountered
	// in decoding and the packet was only partially decoded.
	ErrorLayer() ErrorLayer

	// Key for mapping packets to connections
	FlowKey() (FlowKey, error)
}

type specificLayers struct {
	// Pointers to the various important layers
	link        LinkLayer
	network     NetworkLayer
	transport   TransportLayer
	application ApplicationLayer
	failure     ErrorLayer
}

type packet struct {
	// data contains the entire packet data for a packet
	data []byte
	// encoded contains all the packet data we have yet to decode
	encoded []byte
	// layers contains each layer we've already decoded
	layers []Layer
	// decoder is the next decoder we should call (lazily)
	decoder decoder

	// The set of specific layers we have pointers to.
	specificLayers
}

func (p *packet) LinkLayer() LinkLayer {
	for p.link == nil && p.decodeNextLayer() != nil {
	}
	return p.link
}
func (p *packet) NetworkLayer() NetworkLayer {
	for p.network == nil && p.decodeNextLayer() != nil {
	}
	return p.network
}
func (p *packet) TransportLayer() TransportLayer {
	for p.transport == nil && p.decodeNextLayer() != nil {
	}
	return p.transport
}
func (p *packet) ApplicationLayer() ApplicationLayer {
	for p.application == nil && p.decodeNextLayer() != nil {
	}
	return p.application
}
func (p *packet) ErrorLayer() ErrorLayer {
	for p.failure == nil && p.decodeNextLayer() != nil {
	}
	return p.failure
}

func (p *packet) Data() []byte {
	return p.data
}

func (p *packet) appendLayer(l Layer) {
	p.layers = append(p.layers, l)
}

func newPacket(data []byte, lazy DecodeMethod, d decoder) Packet {
	p := &packet{
		data:    data,
		encoded: data,
		decoder: d,
		// We start off with a size-4 slice since growing a size-zero slice actually
		// can take us a large amount of time, and we expect most packets to give us
		// 4 layers (link, network, transport, application).  This gives our 4-layer
		// benchmark (DecodeNotLazy) a speedup of ~10% (2150ns -> 1922ns)
		layers: make([]Layer, 0, 4),
	}
	if !lazy {
		p.Layers()
	}
	return p
}

// decodeNextLayer decodes the next layer, updates the payload, and returns it.
// Returns nil if there are no more layers to decode.
func (p *packet) decodeNextLayer() (out Layer) {
	defer func() {
		if r := recover(); r != nil {
			fail := &DecodeFailure{data: p.encoded, err: errors.New(fmt.Sprint("Decode failure:", r))}
			p.appendLayer(fail)
			p.failure = fail
			p.encoded = nil
			p.decoder = nil
			out = p.failure
		}
	}()
	if p.decoder == nil || len(p.encoded) == 0 {
		return nil
	}
	result := p.decoder.decode(p.encoded, &p.specificLayers)
	if result.err != nil {
		p.encoded = nil
		p.decoder = nil
		p.failure = &DecodeFailure{data: p.encoded, err: result.err}
		out = p.failure
	} else {
		p.encoded = result.left
		p.decoder = result.next
		out = result.layer
	}
	p.appendLayer(out)
	return out
}

func (p *packet) Layers() []Layer {
	for p.decodeNextLayer() != nil {
	}
	return p.layers
}

func (p *packet) Layer(t LayerType) Layer {
	for _, l := range p.layers {
		if l.LayerType() == t {
			return l
		}
	}
	for l := p.decodeNextLayer(); l != nil; l = p.decodeNextLayer() {
		if l.LayerType() == t {
			return l
		}
	}
	return nil
}

func (p *packet) String() string {
	layers := []string{}
	for l := range p.Layers() {
		layers = append(layers, fmt.Sprintf("%#v", l))
	}
	return fmt.Sprintf("PACKET [%s]", strings.Join(layers, ", "))
}

func (p *packet) FlowKey() (FlowKey, error) {
	if net := p.NetworkLayer(); net == nil {
		return FlowKey{}, errors.New("Packet has no network layer")
	} else if trans := p.TransportLayer(); trans == nil {
		return FlowKey{}, errors.New("Packet has no transport layer")
	} else {
		return NewFlowKey(net, trans), nil
	}
	panic("Should never reach here")
}
