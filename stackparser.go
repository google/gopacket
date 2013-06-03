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

// ParserNoMoreBytes is returned when a parser wants to parse more layers but
// has run out of bytes to parse.
var ParserNoMoreBytes = errors.New("decode has no more bytes to process, so cannot proceed")

// DecodingLayerParser parses a given set of layer types.
type DecodingLayerParser struct {
	DecodingLayerParserOptions
	first    LayerType
	decoders map[LayerType]DecodingLayer
	df       DecodeFeedback
	// Truncated is set when a decode layer detects that the packet has been
	// truncated.
	Truncated bool
}

// AddDecodingLayer adds a decoding layer to the parser.  This adds support for
// the decoding layer's CanDecode layers to the parser... should they be
// encountered, they'll be parsed.
func (l *DecodingLayerParser) AddDecodingLayer(d DecodingLayer) {
	for _, typ := range d.CanDecode().LayerTypes() {
		l.decoders[typ] = d
	}
}

func (l *DecodingLayerParser) SetTruncated() {
	l.Truncated = true
}

// NewDecodingLayerParser creates a new DecodingLayerParser and adds in all
// of the given DecodingLayers with AddDecodingLayer.
func NewDecodingLayerParser(first LayerType, decoders ...DecodingLayer) *DecodingLayerParser {
	dlp := &DecodingLayerParser{
		DecodingLayerParserOptions: HandlePanic,
		decoders:                   make(map[LayerType]DecodingLayer),
		first:                      first,
	}
	dlp.df = dlp // Cast this once to the interface
	for _, d := range decoders {
		dlp.AddDecodingLayer(d)
	}
	return dlp
}

// DecodeLayers decodes as many layers as possible from the given data.  It
// initially treats the data as layer type 'typ', then uses NextLayerType on
// each subsequent decoded layer until it gets to a layer type it doesn't know
// how to parse.
//
// For each layer successfully decoded, DecodeLayers appends the layer type to
// the decoded slice.  DecodeLayers truncates the 'decoded' slice initially, so
// there's no need to empty it yourself.
//
// This decoding method is about an order of magnitude faster than packet
// decoding, because it only decodes known layers that have already been
// allocated.  This means it doesn't need to allocate each layer it returns...
// instead it overwrites the layers that already exist.
//
// Example usage:
//    func main() {
//      var eth layers.Ethernet
//      var ip4 layers.IPv4
//      var ip6 layers.IPv6
//      var tcp layers.TCP
//      var udp layers.UDP
//      var payload gopacket.Payload
//      parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &payload)
//      var source gopacket.PacketDataSource = getMyDataSource()
//      decodedLayers := make([]gopacket.LayerType, 0, 10)
//      for {
//        data, _, err := source.ReadPacketData()
//        if err == nil {
//          fmt.Println("Error reading packet data: ", err)
//          continue
//        }
//        fmt.Println("Decoding packet")
//        err = parser.DecodeLayers(data, gopacket.NilDecodeFeedback, layers.LayerTypeEthernet, &DecodeLayers)
//        for _, typ := range decodedLayers {
//          fmt.Println("  Successfully decoded layer type", typ)
//          switch typ {
//            case layers.LayerTypeEthernet:
//              fmt.Println("    Eth ", eth.SrcMAC, eth.DstMAC)
//            case layers.LayerTypeIPv4:
//              fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
//            case layers.LayerTypeIPv6:
//              fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
//            case layers.LayerTypeTCP:
//              fmt.Println("    TCP ", tcp.SrcPort, tcp.DstPort)
//            case layers.LayerTypeUDP:
//              fmt.Println("    UDP ", udp.SrcPort, udp.DstPort)
//          }
//        }
//        if decodedLayers.Truncated {
//          fmt.Println("  Packet has been truncated")
//        }
//        if err != nil {
//          fmt.Println("  Error encountered:", err)
//        }
//      }
//    }
func (l *DecodingLayerParser) DecodeLayers(data []byte, decoded *[]LayerType) (err error) {
	if l.HandlePanic {
		defer panicToError(&err)
	}
	typ := l.first
	*decoded = (*decoded)[:0] // Truncated decoded layers.
	for len(data) > 0 {
		decoder, ok := l.decoders[typ]
		if !ok {
			return fmt.Errorf("DecodingLayerParser has no decoder for layer type %v", typ)
		} else if err = decoder.DecodeFromBytes(data, l.df); err != nil {
			return err
		}
		*decoded = append(*decoded, typ)
		typ = decoder.NextLayerType()
		data = decoder.LayerPayload()
	}
	return nil
}

func panicToError(e *error) {
	if r := recover(); r != nil {
		*e = fmt.Errorf("panic: %v", r)
	}
}

type DecodingLayerParserOptions struct {
	HandlePanic bool
}

var HandlePanic = DecodingLayerParserOptions{HandlePanic: true}
var DontHandlePanic = DecodingLayerParserOptions{HandlePanic: false}

type nilDecodeFeedback struct{}

func (n *nilDecodeFeedback) SetTruncated() {}

var NilDecodeFeedback = DecodeFeedback(&nilDecodeFeedback{})
