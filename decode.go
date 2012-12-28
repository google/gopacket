// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"encoding/hex"
	"errors"
)

// PacketBuilder is used by layer decoders to store the layers they've decoded,
// and to defer future decoding via NextDecoder.
// Typically, the pattern for use is:
//  func (m *myDecoder) Decode(data []byte, c PacketBuilder) error {
//    if myLayer, err := myDecodingLogic(data); err != nil {
//      return err
//    } else {
//      c.AddLayer(myLayer)
//    }
//    // maybe do this, if myLayer is a LinkLayer
//    c.SetLinkLayer(myLayer)
//    return c.NextDecoder(nextDecoder)
//  }
type PacketBuilder interface {
	// AddLayer should be called by a decoder immediately upon successful
	// decoding of a layer.
	AddLayer(l Layer)
	// The following functions set the various specific layers in the final
	// packet.  Note that if many layers call SetX, the first call is kept and all
	// other calls are ignored.
	SetLinkLayer(LinkLayer)
	SetNetworkLayer(NetworkLayer)
	SetTransportLayer(TransportLayer)
	SetApplicationLayer(ApplicationLayer)
	SetErrorLayer(ErrorLayer)
	// NextDecoder should be called by a decoder when they're done decoding a
	// packet layer but not done with decoding the entire packet.  The next
	// decoder will be called to decode the last AddLayer's LayerPayload.
	// Because of this, NextDecoder must only be called once all other
	// PacketBuilder calls have been made.  Set*Layer and AddLayer calls after
	// NextDecoder calls will behave incorrectly.
	NextDecoder(next Decoder) error
}

// Decoder is an interface for logic to decode a packet layer.  Users may
// implement a Decoder to handle their own strange packet types, or may use one
// of the many decoders available in the 'layers' subpackage to decode things
// for them.
type Decoder interface {
	// Decode decodes the bytes of a packet, sending decoded values and other
	// information to PacketBuilder, and returning an error if unsuccessful.  See
	// the PacketBuilder documentation for more details.
	Decode([]byte, PacketBuilder) error
}

// DecodeFunc wraps a function to make it a Decoder.
type DecodeFunc func([]byte, PacketBuilder) error

func (d DecodeFunc) Decode(data []byte, c PacketBuilder) error {
	// function, call thyself.
	return d(data, c)
}

// DecodePayload is a Decoder that returns a Payload layer containing all
// remaining bytes.
var DecodePayload Decoder = DecodeFunc(decodePayload)

// DecodeUnknown is a Decoder that returns a DecodeFailure layer containing all
// remaining bytes, useful if you run up against a layer that you're unable to
// decode yet.
var DecodeUnknown Decoder = DecodeFunc(decodeUnknown)

// LayerTypeDecodeFailure is the layer type for the default error layer.
var LayerTypeDecodeFailure LayerType = RegisterLayerType(0, LayerTypeMetadata{"Decode Failure", DecodeUnknown})

// LayerTypePayload is the layer type for a payload that we don't try to decode
// but treat as a success, IE: an application-level payload.
var LayerTypePayload LayerType = RegisterLayerType(1, LayerTypeMetadata{"Payload", DecodePayload})

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
func (d *DecodeFailure) String() string        { return hex.Dump(d.data) }

// LayerType returns LayerTypeDecodeFailure
func (d *DecodeFailure) LayerType() LayerType { return LayerTypeDecodeFailure }

// decodeUnknown "decodes" unsupported data types by returning an error.
// This decoder will thus always return a DecodeFailure layer.
func decodeUnknown(data []byte, c PacketBuilder) error {
	return errors.New("Layer type not currently supported")
}

// decodePayload decodes data by returning it all in a Payload layer.
func decodePayload(data []byte, c PacketBuilder) error {
	payload := &Payload{Data: data}
	c.AddLayer(payload)
	return nil
}
