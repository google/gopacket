// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"errors"
)

// DecodeResult is returned from a Decode call.  You shouldn't need to use this
// unless you want to write your own packet decoding logic.  Most users can
// ignore this struct.
type DecodeResult struct {
	// DecodedLayer is the layer we've created with this decode call.
	// DecodedLayer.LayerPayload() is the next set of bytes to be decoded... if it
	// is empty, we stop decoding.
	DecodedLayer Layer
	// NextDecoder is the next decoder to call.  When NextDecoder == nil, the
	// packet considers itself fully decoded.
	NextDecoder Decoder
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

// Decoder is an interface for logic to decode a packet layer.  See DecodeResult
// for a long-winded explanation of the data this fuction returns.  Users may
// implement a Decoder to handle their own strange packet types, or may use one
// of the many decoders available in the 'layers' subpackage to decode things
// for them.
type Decoder interface {
	Decode([]byte) (DecodeResult, error)
}

// DecodeFunc wraps a function to make it a Decoder.
type DecodeFunc func([]byte) (DecodeResult, error)

func (d DecodeFunc) Decode(data []byte) (DecodeResult, error) {
	// function, call thyself.
	return d(data)
}

// DecodeFailure is a packet layer created if decoding of the packet data failed
// for some reason.  It implements ErrorLayer.
type DecodeFailure struct {
	data []byte
	err  error
}

// Error returns the error encountered during decoding.
func (d *DecodeFailure) Error() error          { return d.err }
func (d *DecodeFailure) LayerContents() []byte { return d.data }
func (d *DecodeFailure) LayerPayload() []byte  { return nil }

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

// LayerType returns LayerTypeDecodeFailure
func (d *DecodeFailure) LayerType() LayerType { return LayerTypeDecodeFailure }

// decodeUnknown "decodes" unsupported data types by returning an error.
// This decoder will thus always return a DecodeFailure layer.
func decodeUnknown(data []byte) (out DecodeResult, err error) {
	err = errors.New("Layer type not currently supported")
	return
}

// decodePayload decodes data by returning it all in a Payload layer.
func decodePayload(data []byte) (out DecodeResult, err error) {
	payload := &Payload{Data: data}
	out.DecodedLayer = payload
	out.ApplicationLayer = payload
	return
}
