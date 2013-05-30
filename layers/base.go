// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

// BaseLayer is a convenience struct which implements the LayerData and
// LayerPayload functions of the Layer interface.
type BaseLayer struct {
	// Contents is the set of bytes that make up this layer.  IE: for an
	// Ethernet packet, this would be the set of bytes making up the
	// Ethernet frame.
	Contents []byte
	// Payload is the set of bytes contained by (but not part of) this
	// Layer.  Again, to take Ethernet as an example, this would be the
	// set of bytes encapsulated by the Ethernet protocol.
	Payload []byte
}

// LayerContents returns the bytes of the packet layer.
func (b *BaseLayer) LayerContents() []byte { return b.Contents }

// LayerPayload returns the bytes contained within the packet layer.
func (b *BaseLayer) LayerPayload() []byte { return b.Payload }
