// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"errors"
)

// SpecificLayers contains pointers to specific layer types.
type SpecificLayers struct {
	// If the DecodedLayer is one of these layer types, also point to it here.
	// The first of each of these will be returned by Packet.*Layer().  IE: if
	// we've got an IPv4 packet encapsulated in another IPv4 packet, the decoder
	// should point NetworkLayer at each of them, and packet will use the first
	// (outermost) of these as its NetworkLayer().
	LinkLayer
	NetworkLayer
	TransportLayer
	ApplicationLayer
	ErrorLayer
}

// LayerCollector is used by layer decoders to store the layers they've decoded,
// and to defer future decoding via NextDecoder.
// Typically, the pattern for use is:
//  func (m *myDecoder) Decode(data []byte, c LayerCollector) error {
//    if myLayer, err := myDecodingLogic(data); err != nil {
//      return err
//    } else {
//      c.DecodedLayer(myLayer)
//    }
//    // maybe do this, if myLayer is a LinkLayer
//    c.SpecificLayers(SpecificLayers{LinkLayer: myLayer})
//    return c.NextDecoder(nextDecoder)
//  }
type LayerCollector interface {
  // DecodedLayer should be called by a decoder immediately upon successful
  // decoding of a layer.
	DecodedLayer(l Layer)
  // SpecificLayers should be called by a decoder if they have a decoded layer
  // they'd like specific layer calls to point to.
  SpecificLayers(s SpecificLayers)
  // NextDecoder should be called by a decoder when they're done decoding a
  // packet layer but not done with decoding the entire packet.  The next
  // decoder will be called to decode the last DecodedLayer's LayerPayload.
	NextDecoder(next Decoder) error
}

// Decoder is an interface for logic to decode a packet layer.  See DecodeResult
// for a long-winded explanation of the data this fuction returns.  Users may
// implement a Decoder to handle their own strange packet types, or may use one
// of the many decoders available in the 'layers' subpackage to decode things
// for them.
type Decoder interface {
  // Decode decodes the bytes of a packet, sending decoded values and other
  // information to LayerCollector, and returning an error if unsuccessful.  See
  // the LayerCollector documentation for more details.
	Decode([]byte, LayerCollector) error
}

type layerList interface {
  // get returns the i-th layer, or nil if there isn't one.
  func get(i int) Layer
  // getAll returns all layers as a slice.
  func getAll() []Layer
}

// eagerCollector is an eager LayerCollector.
type eagerCollector struct {
	layers []Layer
	last   Layer
}
func (s *eagerCollector) AddLayer(l Layer) {
	s.layers = append(s.layers, l)
	s.last = l
}
func (s *eagerCollector) NextDecoder(next Decoder) error {
  // Since we're eager, immediately call the next decoder.
	return next.Decode(s.last.LayerPayload(), s)
}
func (s *eagerCollector) get(i int) Layer {
  if i < len(s.layers) {
    return s.layers[i]
  }
  return nil
}
func (s *eagerCollector) getAll() []Layer {
  return s.layers
}

// DecodeFunc wraps a function to make it a Decoder.
type DecodeFunc func([]byte, LayerCollector) error

func (d DecodeFunc) Decode(data []byte, c LayerCollector) error {
	// function, call thyself.
	return d(data, c)
}

var (
	// DecodePayload is a Decoder that returns a Payload layer containing all
	// remaining bytes.
	DecodePayload Decoder = DecodeFunc(decodePayload)
	// DecodeUnknown is a Decoder that returns a DecodeFailure layer containing all
	// remaining bytes, useful if you run up against a layer that you're unable to
	// decode yet.
	DecodeUnknown Decoder = DecodeFunc(decodeUnknown)
	// LayerTypeDecodeFailure is the layer type for the default error layer.
	LayerTypeDecodeFailure = RegisterLayerType(0, LayerTypeMetadata{"Decode Failure", DecodeUnknown})
	// LayerTypePayload is the layer type for a payload that we don't try to decode
	// but treat as a success, IE: an application-level payload.
	LayerTypePayload = RegisterLayerType(1, LayerTypeMetadata{"Payload", DecodePayload})
)

// DecodeFailure is a packet layer created if decoding of the packet data failed
// for some reason.  It implements ErrorLayer.  LayerContents will be the entire
// set of bytes that failed to parse, and Error will return the reason parsing
// failed.
type DecodeFailure struct {
	data []byte
	err  error
}

// Error returns the error encountered during decoding.
func (d *DecodeFailure) Error() error          { return d.err }
func (d *DecodeFailure) LayerContents() []byte { return d.data }
func (d *DecodeFailure) LayerPayload() []byte  { return nil }

// LayerType returns LayerTypeDecodeFailure
func (d *DecodeFailure) LayerType() LayerType { return LayerTypeDecodeFailure }

// decodeUnknown "decodes" unsupported data types by returning an error.
// This decoder will thus always return a DecodeFailure layer.
func decodeUnknown(data []byte, c LayerCollector) error {
	return errors.New("Layer type not currently supported")
}

// decodePayload decodes data by returning it all in a Payload layer.
func decodePayload(data []byte, c LayerCollector) error {
	payload := &Payload{Data: data}
	c.AddLayer(payload)
	return nil
}
