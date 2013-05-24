// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

import (
	"errors"
	"fmt"
)

// DecodingLayer is an interface for packet layers that can decode themselves.
type DecodingLayer interface {
	DecodeFromBytes(data []byte, df DecodeFeedback) error
	CanDecode() LayerClass
	NextLayerType() LayerType
	// LayerPayload is the set of bytes remaining to decode after a call to
	// DecodeFromBytes.
	LayerPayload() []byte
}

// ParserDecodeMismatch is returned when a parser sees that the next layer type
// to be parsed does not match any of the parsers available to parse.
var ParserDecodeMismatch = errors.New("decode of next layer type cannot be performed by next decoder")

// ParserNoMoreBytes is returned when a parser wants to parse more layers but
// has run out of bytes to parse.
var ParserNoMoreBytes = errors.New("decode has no more bytes to process, so cannot proceed")

// StackParser is an extremely fast parser for known packet stacks.  If you know
// in advance what the packets you care about are going to look like, use
// StackParser instead of Packet and you'll get extremely improved performance
// (~10-20x).  This speed-up comes from the fact that since we know what the
// stack should look like, we can preallocate all layers for that stack,
// bypassing any need to do memory allocation, our primary slow-down in packet
// processing.
//
// Note that StackParser acts like a NoCopy decoder: the layers will reference
// into the initial byte slice, so it should either be copied before calling
// DecodeBytes or not modified while the decoded layers are being used.
//
// Not all layers are DecodingLayers, and not all DecodingLayers are Layers, though
// we're working on porting as much as possible to work everywhere.  Note that
// StackParser is itself a DecodingLayer, which can be helpful if you're expecting
// multiple packet types that share some portion of their stack.
//
// You can implement branching based on how far along decoding went, since the
// first element returned by DecodeBytes is the number of layers successfully
// decoded.
//
// Example:
//
//   func main() {
//     myPacketData := []byte{...}
//     var l1 Ethernet
//     var l2 IPv4
//     var l3_1 TCP
//     var l3_2 UDP
//     var l4 Payload
//     var feedback gopacket.SimpleDecodeFeedback
//     parser1 := StackParser{&l1, &l2, &l3_1, &l4}
//     parser2 := StackParser{&l3_2, &l4}
//     n, remaining, err := parser1.DecodeBytes(myPacketData, &feedback)
//     switch n {
//       case 0, 1:
//         fmt.Println("Unable to decode up to IPv4 header:", err)
//       case 2:  // We got through IPv4, let's see if we have a UDP packet instead...
//         if l2.NextLayerType() == LayerTypeUDP {
//           _, _, err = parser2.DecodeBytes(remaining, &feedback)
//           ...
//         } else {
//           fmt.Println("Not TCP or UDP packet")
//         }
//       case 3:
//         fmt.Println("TCP packet has no payload")
//       case 4:
//         fmt.Println("Fully parsed TCP packet, including payload")
//     }
//   }
type StackParser []DecodingLayer

type SimpleDecodeFeedback struct {
	Truncated bool
}

func (s *SimpleDecodeFeedback) SetTruncated() {
	s.Truncated = true
}

func panicToError(e *error) {
	if r := recover(); r != nil {
		*e = fmt.Errorf("panic: %v", r)
	}
}

type StackParserDecodeOptions struct {
	HandlePanic bool
}

var HandlePanic = StackParserDecodeOptions{HandlePanic: true}
var DontHandlePanic = StackParserDecodeOptions{HandlePanic: false}

// DecodeBytes attempts to decode a set of bytes into the set of DecodingLayers
// that make up this stack.  It returns the number of layers successfully
// decoded (in range [0, len(s)]), the set of bytes remaining after all
// successful decoding was completed, and any error encountered along the way.
//
//   e == nil iff n == len(s)
//
// Will return the error ParserDecodeMismatch if a subsequent layer
// type (as returned by DecodingLayers.NextLayerType) cannot be handled by a
// subsequent DecodingLayer (as returned by DecodingLayers.CanDecode).
//
// Will return the error ParserNoMoreBytes if all bytes are decoded before all
// DecodingLayers are called.
func (s StackParser) DecodeBytes(data []byte, df DecodeFeedback, opts StackParserDecodeOptions) (n int, remaining []byte, e error) {
	if opts.HandlePanic {
		defer panicToError(&e)
	}
	for i, d := range s {
		if err := d.DecodeFromBytes(data, df); err != nil {
			return i, data, err
		}
		data = d.LayerPayload()
		if i < len(s)-1 {
			if len(data) == 0 {
				// We have more layers to parse, but no more data.
				return i + 1, nil, ParserNoMoreBytes
			}
			if !s[i+1].CanDecode().Contains(d.NextLayerType()) {
				// The next layer can't handle parsing the bytes we have.
				return i + 1, data, ParserDecodeMismatch
			}
		}
	}
	return len(s), data, nil
}

// DecodeFromBytes calls DecodeBytes and discards n.  It's given to enable users
// to use StackParser as a DecodingLayer.
func (s StackParser) DecodeFromBytes(data []byte, df DecodeFeedback) (remaining []byte, err error) {
	_, remaining, err = s.DecodeBytes(data, df, DontHandlePanic)
	return
}

// CanDecode returns the layer class the first layer in the stack can decode.
func (s StackParser) CanDecode() LayerClass {
	return s[0].CanDecode()
}

// NextLayerType returns the next layer type of the last layer in the stack.
func (s StackParser) NextLayerType() LayerType {
	return s[len(s)-1].NextLayerType()
}

type nilDecodeFeedback struct{}

func (n *nilDecodeFeedback) SetTruncated() {}

// If you don't care about the feedback returned from decode functions, you can
// pass this DecodeFeedback in, and they'll be ignored.
var NilDecodeFeedback DecodeFeedback = &nilDecodeFeedback{}
