// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"errors"
)

type LinkType int

const (
	// According to pcap-linktype(7).
	LINKTYPE_NULL             LinkType = 0
	LINKTYPE_ETHERNET         LinkType = 1
	LINKTYPE_TOKEN_RING       LinkType = 6
	LINKTYPE_ARCNET           LinkType = 7
	LINKTYPE_SLIP             LinkType = 8
	LINKTYPE_PPP              LinkType = 9
	LINKTYPE_FDDI             LinkType = 10
	LINKTYPE_ATM_RFC1483      LinkType = 100
	LINKTYPE_RAW              LinkType = 101
	LINKTYPE_PPP_HDLC         LinkType = 50
	LINKTYPE_PPP_ETHER        LinkType = 51
	LINKTYPE_C_HDLC           LinkType = 104
	LINKTYPE_IEEE802_11       LinkType = 105
	LINKTYPE_FRELAY           LinkType = 107
	LINKTYPE_LOOP             LinkType = 108
	LINKTYPE_LINUX_SLL        LinkType = 113
	LINKTYPE_LTALK            LinkType = 104
	LINKTYPE_PFLOG            LinkType = 117
	LINKTYPE_PRISM_HEADER     LinkType = 119
	LINKTYPE_IP_OVER_FC       LinkType = 122
	LINKTYPE_SUNATM           LinkType = 123
	LINKTYPE_IEEE802_11_RADIO LinkType = 127
	LINKTYPE_ARCNET_LINUX     LinkType = 129
	LINKTYPE_LINUX_IRDA       LinkType = 144
	LINKTYPE_LINUX_LAPD       LinkType = 177
)

func (l LinkType) decode(data []byte, s *specificLayers) (out decodeResult) {
	switch l {
	case LINKTYPE_ETHERNET:
		return decodeEthernet(data, s)
	}
	out.err = errors.New("Unsupported link-layer type")
	return
}

func (l LinkType) Decode(data []byte, lazy DecodeMethod) Packet {
	return newPacket(data, lazy, l)
}

type Packet interface {
	// Returns all data associated with this packet
	Data() []byte
	// Returns all layers in this packet, computing them as necessary
	Layers() []Layer
	// Returns the first layer in this packet of the given type, or nil
	Layer(LayerType) Layer
	// Returns the data layer type
	LinkType() LinkType
	// Printable
	String() string
	// Accessors to specific commonly-available layers, return nil if the layer
	// doesn't exist or hasn't been computed yet.
	LinkLayer() LinkLayer
	NetworkLayer() NetworkLayer
	TransportLayer() TransportLayer
	ApplicationLayer() ApplicationLayer
}

type specificLayers struct {
	// Pointers to the various important layers
	link        LinkLayer
	network     NetworkLayer
	transport   TransportLayer
	application ApplicationLayer
}

func (s *specificLayers) LinkLayer() LinkLayer {
	return s.link
}
func (s *specificLayers) NetworkLayer() NetworkLayer {
	return s.network
}
func (s *specificLayers) TransportLayer() TransportLayer {
	return s.transport
}
func (s *specificLayers) ApplicationLayer() ApplicationLayer {
	return s.application
}

type packet struct {
	// data contains the entire packet data for a packet
	data []byte
	// encoded contains all the packet data we have yet to decode
	encoded []byte
	// layers contains each layer we've already decoded
	layers []Layer
	// linkType contains the link type for the underlying transport
	linkType LinkType
	// decoder is the next decoder we should call (lazily)
	decoder decoder

	// The set of specific layers we have pointers to.
	specificLayers
}

func (p *packet) Data() []byte {
	return p.data
}
func (p *packet) LinkType() LinkType {
	return p.linkType
}

func (p *packet) appendLayer(l Layer) {
	p.layers = append(p.layers, l)
}
