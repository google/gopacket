// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"errors"
	"fmt"
	"strings"
)

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
