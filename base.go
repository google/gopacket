// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

import (
	"encoding/hex"
	"fmt"
)

// Layer represents a single decoded packet layer (using either the
// OSI or TCP/IP definition of a layer).  When decoding, a packet's data is
// broken up into a number of layers.  The caller may call LayerType() to
// figure out which type of layer he's received from the packet.  Optionally,
// he may then use a type assertion to get the actual layer type for deep
// inspection of the data.
type Layer interface {
	fmt.Stringer
	// LayerType is the gopacket type for this layer.
	LayerType() LayerType
	// LayerContents returns the set of bytes that make up this layer.
	LayerContents() []byte
	// LayerPayload returns the set of bytes contained within this layer, not
	// including the layer itself.
	LayerPayload() []byte
}

// Payload is a Layer containing the payload of a packet.  The definition of
// what constitutes the payload of a packet depends on previous layers; for
// TCP and UDP, we stop decoding above layer 4 and return the remaining
// bytes as a Payload.  Payload is an ApplicationLayer.
type Payload struct {
	Data []byte
}

// LayerType returns LayerTypePayload
func (p *Payload) LayerType() LayerType  { return LayerTypePayload }
func (p *Payload) LayerContents() []byte { return p.Data }
func (p *Payload) LayerPayload() []byte  { return nil }
func (p *Payload) Payload() []byte       { return p.Data }
func (p *Payload) String() string        { return hex.Dump(p.Data) }

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
	NetworkFlow() Flow
}

// TransportLayer is the packet layer corresponding to the TCP/IP layer 3 (OSI
// layer 4)
type TransportLayer interface {
	Layer
	TransportFlow() Flow
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
	Error() error
}
