// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"errors"
	"fmt"
	"strings"
)

type Packet interface {
	// Returns all data associated with this packet
	Data() []byte
	// Returns all layers in this packet, computing them as necessary
	Layers() []Layer
	// Returns the first layer in this packet of the given type, or nil
	Layer(LayerType) Layer
	// Returns the data layer type
	LinkType() LinkType
	// Printable
	String() string
	// Accessors to specific commonly-available layers, return nil if the layer
	// doesn't exist or hasn't been computed yet.
	LinkLayer() LinkLayer
	NetworkLayer() NetworkLayer
	TransportLayer() TransportLayer
	ApplicationLayer() ApplicationLayer
}

type specificLayers struct {
	// Pointers to the various important layers
	link        LinkLayer
	network     NetworkLayer
	transport   TransportLayer
	application ApplicationLayer
}

type packet struct {
	// data contains the entire packet data for a packet
	data []byte
	// encoded contains all the packet data we have yet to decode
	encoded []byte
	// layers contains each layer we've already decoded
	layers []Layer
	// linkType contains the link type for the underlying transport
	linkType LinkType
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

func (p *packet) Data() []byte {
	return p.data
}
func (p *packet) LinkType() LinkType {
	return p.linkType
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
			p.appendLayer(&DecodeFailure{Data: p.encoded, Error: errors.New(fmt.Sprint("Decode failure:", r))})
			p.encoded = nil
			p.decoder = nil
		}
	}()
	if p.decoder == nil || len(p.encoded) == 0 {
		return nil
	}
	result := p.decoder.decode(p.encoded, &p.specificLayers)
	if result.err != nil {
		p.encoded = nil
		p.decoder = nil
		out = &DecodeFailure{Data: p.encoded, Error: result.err}
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
