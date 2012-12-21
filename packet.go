// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// CaptureInfo contains capture metadata for a packet.  If a packet was captured
// off the wire or read from a pcap file (see the 'pcap' subdirectory), this
// information will be attached to the packet.
type CaptureInfo struct {
	// Populated is set to true if the rest of the CaptureInfo has been populated
	// with actual information.  If Populated is false, there's no point in
	// reading any of the other fields.
	Populated             bool
	Timestamp             time.Time
	CaptureLength, Length int
}

// Packet is the primary object used by gopacket.  Packets are created by a
// Decoder's Decode call.  A packet is made up of a set of Data, which
// is broken into a number of Layers as it is decoded.
type Packet interface {
	// Data returns all data associated with this packet
	Data() []byte
	// Layers returns all layers in this packet, computing them as necessary
	Layers() []Layer
	// Layer returns the first layer in this packet of the given type, or nil
	Layer(LayerType) Layer
	// LayerClass returns the first layer in this packet of the given class,
	// or nil.
	LayerClass(LayerClass) Layer
	// String returns a human-readable string.
	String() string
	// CaptureInfo returns the caputure information for this packet.  This returns
	// a pointer to the packet's struct, so it can be used both for reading and
	// writing the information.
	CaptureInfo() *CaptureInfo

	// LinkLayer returns the first link layer in the packet
	LinkLayer() LinkLayer
	// NetworkLayer returns the first network layer in the packet
	NetworkLayer() NetworkLayer
	// TransportLayer returns the first transport layer in the packet
	TransportLayer() TransportLayer
	// ApplicationLayer returns the first application layer in the packet
	ApplicationLayer() ApplicationLayer
	// ErrorLayer is particularly useful, since it returns nil if the packet
	// was fully decoded successfully, and non-nil if an error was encountered
	// in decoding and the packet was only partially decoded.  Thus, its output
	// can be used to determine if the entire packet was able to be decoded.
	ErrorLayer() ErrorLayer
}

// packet contains all the information we need to fulfill the Packet interface,
// and its two "subclasses" (yes, no such thing in Go, bear with me),
// eagerPacket and lazyPacket, provide eager and lazy decoding logic around the
// various functions needed to access this information.
type packet struct {
	// data contains the entire packet data for a packet
	data []byte
	// layers contains each layer we've already decoded
	layers []Layer
	// last is the last layer added to the packet
	last Layer
	// capInfo is the CaptureInfo for this packet
	capInfo CaptureInfo

	// Pointers to the various important layers
	link        LinkLayer
	network     NetworkLayer
	transport   TransportLayer
	application ApplicationLayer
	failure     ErrorLayer
}

func (p *packet) SetLinkLayer(l LinkLayer) {
	if p.link == nil {
		p.link = l
	}
}
func (p *packet) SetNetworkLayer(l NetworkLayer) {
	if p.network == nil {
		p.network = l
	}
}
func (p *packet) SetTransportLayer(l TransportLayer) {
	if p.transport == nil {
		p.transport = l
	}
}
func (p *packet) SetApplicationLayer(l ApplicationLayer) {
	if p.application == nil {
		p.application = l
	}
}
func (p *packet) SetErrorLayer(l ErrorLayer) {
	if p.failure == nil {
		p.failure = l
	}
}
func (p *packet) AddLayer(l Layer) {
	p.layers = append(p.layers, l)
	p.last = l
}
func (p *packet) CaptureInfo() *CaptureInfo {
	return &p.capInfo
}
func (p *packet) Data() []byte {
	return p.data
}
func (p *packet) recoverDecodeError() {
	if r := recover(); r != nil {
		fail := &DecodeFailure{err: fmt.Errorf("BLAH")}
		if p.last == nil {
			fail.data = p.data
		} else {
			fail.data = p.last.LayerPayload()
		}
		p.AddLayer(fail)
	}
}
func packetString(pLayers []Layer) string {
	layers := []string{}
	for l := range pLayers {
		layers = append(layers, fmt.Sprintf("%#v", l))
	}
	return fmt.Sprintf("PACKET [%s]", strings.Join(layers, ", "))
}

type eagerPacket struct {
	packet
}

func (p *eagerPacket) NextDecoder(next Decoder) error {
	if p.last == nil {
		return errors.New("NextDecoder called, but no layers added yet")
	}
	// Since we're eager, immediately call the next decoder.
	return next.Decode(p.last.LayerPayload(), p)
}
func (p *eagerPacket) initialDecode(dec Decoder) {
	defer p.recoverDecodeError()
	err := dec.Decode(p.data, p)
	if err != nil {
		panic(err)
	}
}
func (p *eagerPacket) LinkLayer() LinkLayer {
	return p.link
}
func (p *eagerPacket) NetworkLayer() NetworkLayer {
	return p.network
}
func (p *eagerPacket) TransportLayer() TransportLayer {
	return p.transport
}
func (p *eagerPacket) ApplicationLayer() ApplicationLayer {
	return p.application
}
func (p *eagerPacket) ErrorLayer() ErrorLayer {
	return p.failure
}
func (p *eagerPacket) Layers() []Layer {
	return p.layers
}
func (p *eagerPacket) Layer(t LayerType) Layer {
	for _, l := range p.layers {
		if l.LayerType() == t {
			return l
		}
	}
	return nil
}
func (p *eagerPacket) LayerClass(lc LayerClass) Layer {
	for _, l := range p.layers {
		if lc.Contains(l.LayerType()) {
			return l
		}
	}
	return nil
}
func (p *eagerPacket) String() string { return packetString(p.Layers()) }

type lazyPacket struct {
	packet
	next Decoder
}

func (p *lazyPacket) NextDecoder(next Decoder) error {
	p.next = next
	return nil
}
func (p *lazyPacket) decodeNextLayer() {
	if p.next == nil {
		return
	}
	d := p.data
	if p.last != nil {
		d = p.last.LayerPayload()
	}
	next := p.next
	p.next = nil
	// We've just set p.next to nil, so if we see we have no data, this should be
	// the final call we get to decodeNextLayer if we return here.
	if len(d) == 0 {
		return
	}
	defer p.recoverDecodeError()
	err := next.Decode(d, p)
	if err != nil {
		panic(err)
	}
}
func (p *lazyPacket) LinkLayer() LinkLayer {
	for p.link == nil && p.next != nil {
		p.decodeNextLayer()
	}
	return p.link
}
func (p *lazyPacket) NetworkLayer() NetworkLayer {
	for p.network == nil && p.next != nil {
		p.decodeNextLayer()
	}
	return p.network
}
func (p *lazyPacket) TransportLayer() TransportLayer {
	for p.transport == nil && p.next != nil {
		p.decodeNextLayer()
	}
	return p.transport
}
func (p *lazyPacket) ApplicationLayer() ApplicationLayer {
	for p.application == nil && p.next != nil {
		p.decodeNextLayer()
	}
	return p.application
}
func (p *lazyPacket) ErrorLayer() ErrorLayer {
	for p.failure == nil && p.next != nil {
		p.decodeNextLayer()
	}
	return p.failure
}
func (p *lazyPacket) Layers() []Layer {
	for p.next != nil {
		p.decodeNextLayer()
	}
	return p.layers
}
func (p *lazyPacket) Layer(t LayerType) Layer {
	for _, l := range p.layers {
		if l.LayerType() == t {
			return l
		}
	}
	numLayers := len(p.layers)
	for p.next != nil {
		p.decodeNextLayer()
		for _, l := range p.layers[numLayers:] {
			if l.LayerType() == t {
				return l
			}
		}
		numLayers = len(p.layers)
	}
	return nil
}
func (p *lazyPacket) LayerClass(lc LayerClass) Layer {
	for _, l := range p.layers {
		if lc.Contains(l.LayerType()) {
			return l
		}
	}
	numLayers := len(p.layers)
	for p.next != nil {
		p.decodeNextLayer()
		for _, l := range p.layers[numLayers:] {
			if lc.Contains(l.LayerType()) {
				return l
			}
		}
		numLayers = len(p.layers)
	}
	return nil
}
func (p *lazyPacket) String() string { return packetString(p.Layers()) }

// DecodeOptions tells gopacket how to decode a packet.
type DecodeOptions struct {
	// Lazy decoding decodes the minimum number of layers needed to return data
	// for a packet at each function call.  Be careful using this with concurrent
	// packet processors, as each call to packet.* could mutate the packet, and
	// two concurrent function calls could interact poorly.
	Lazy bool
	// NoCopy decoding doesn't copy its input buffer into storage that's owned by
	// the packet.  If you can guarantee that the bytes underlying the slice
	// passed into NewPacket aren't going to be modified, this can be faster.  If
	// there's any chance that those bytes WILL be changed, this will invalidate
	// your packets.
	NoCopy bool
}

// Default decoding provides the safest (but slowest) method for decoding
// packets.  It eagerly processes all layers (so it's concurrency-safe) and it
// copies its input buffer upon creation of the packet (so the packet remains
// valid if the underlying slice is modified.  Both of these take time,
// though, so beware.  If you can guarantee that the packet will only be used
// by one goroutine at a time, set Lazy decoding.  If you can guarantee that
// the underlying slice won't change, set NoCopy decoding.
var Default DecodeOptions = DecodeOptions{}

// Lazy is a DecodeOptions with just Lazy set.
var Lazy DecodeOptions = DecodeOptions{Lazy: true}

// NoCopy is a DecodeOptions with just NoCopy set.
var NoCopy DecodeOptions = DecodeOptions{NoCopy: true}

// NewPacket creates a new Packet object from a set of bytes.  The
// firstLayerDecoder tells it how to interpret the first layer from the bytes,
// future layers will be generated from that first layer automatically.
func NewPacket(data []byte, firstLayerDecoder Decoder, options DecodeOptions) Packet {
	if !options.NoCopy {
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		data = dataCopy
	}
	if options.Lazy {
		return &lazyPacket{
			packet: packet{data: data, layers: make([]Layer, 0, 4)},
			next:   firstLayerDecoder,
		}
	}
	p := &eagerPacket{
		packet: packet{data: data, layers: make([]Layer, 0, 4)},
	}
	p.initialDecode(firstLayerDecoder)
	return p
}

type PacketDataSource interface {
	// ReadPacketData returns the next packet available from this data source.
	ReadPacketData() (data []byte, ci CaptureInfo, err error)
}

type PacketSource struct {
	source PacketDataSource
	Decoder
	DecodeOptions
}

func NewPacketSource(source PacketDataSource, decoder Decoder) *PacketSource {
	return &PacketSource{
		source:  source,
		Decoder: decoder,
	}
}

func (p *PacketSource) NextPacket() (Packet, error) {
	data, ci, err := p.source.ReadPacketData()
	if err != nil {
		return nil, err
	}
	packet := NewPacket(data, p.Decoder, p.DecodeOptions)
	*packet.CaptureInfo() = ci
	return packet, nil
}

func (p *PacketSource) PacketChannel() <-chan Packet {
	c := make(chan Packet, 100)
	go func() {
		for {
			packet, err := p.NextPacket()
			if err == io.EOF {
				close(c)
			} else if err == nil {
				c <- packet
			}
		}
	}()
	return c
}
