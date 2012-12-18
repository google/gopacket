// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"errors"
)

// DecodeResult is returned from a Decode call.
type DecodeResult struct {
	// DecodedLayer is the layer we've created with this decode call.
	DecodedLayer Layer
	// NextDecoder is the next decoder to call.  When NextDecoder == nil, the
	// packet considers itself fully decoded.
	NextDecoder Decoder
	// RemainingBytes is the bytes that are left to be decoded.  When
	// len(RemainingBytes) is 0, the packet considers itself fully decoded.
	RemainingBytes []byte
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

// Decoder decodes the next layer in a packet.  It returns a set of useful
// information, which is used by the packet decoding logic to update packet
// state.  Optionally, the decode function may set any of the specificLayer
// pointers to point to the new layer it has created.
//
// This decoder interface is the internal interface used by gopacket to store
// the next method to use for decoding the rest of the data available in the
// packet.
type Decoder interface {
	Decode([]byte) (DecodeResult, error)
}

// DecodeFunc is an implementation of decoder that's a simple function.
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

// Payload returns the entire payload which failed to be decoded.
func (d *DecodeFailure) Payload() []byte { return d.data }

// Error returns the error encountered during decoding.
func (d *DecodeFailure) Error() error { return d.err }

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
