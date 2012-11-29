// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"errors"
)

// DecodeResult is returned from a Decode() call.
type DecodeResult struct {
	// The layer we've created with this decode call
	DecodedLayer Layer
	// The next decoder to call
	NextDecoder Decoder
	// The bytes that are left to be decoded
	RemainingBytes []byte
	// The specific layers which should be set
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

// decoderFunc is an implementation of decoder that's a simple function.
type decoderFunc func([]byte) (DecodeResult, error)

func (d decoderFunc) Decode(data []byte) (DecodeResult, error) {
	// function, call thyself.
	return d(data)
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

// DecodeFailure is a packet layer created if decoding of the packet data failed
// for some reason.  It implements ErrorLayer.
type DecodeFailure struct {
	data []byte
	err  error
}

// Returns the entire payload which failed to be decoded.
func (d *DecodeFailure) Payload() []byte { return d.data }

// Returns the error encountered during decoding.
func (d *DecodeFailure) Error() error { return d.err }

// Returns LayerTypeDecodeFailure
func (d *DecodeFailure) LayerType() LayerType { return LayerTypeDecodeFailure }

// decodeUnknown "decodes" unsupported data types by returning an error.
// This decoder will thus always return a DecodeFailure layer.
var decodeUnknown decoderFunc = func(data []byte) (out DecodeResult, err error) {
	err = errors.New("Link type not currently supported")
	return
}

// decodePayload decodes data by returning it all in a Payload layer.
var decodePayload decoderFunc = func(data []byte) (out DecodeResult, err error) {
	payload := &Payload{Data: data}
	out.DecodedLayer = payload
	out.ApplicationLayer = payload
	return
}
