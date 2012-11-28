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
	case LINKTYPE_PPP:
		return decodePpp(data, s)
	}
	out.err = errors.New("Unsupported link-layer type")
	return
}

func (l LinkType) Decode(data []byte, lazy DecodeMethod) Packet {
	return newPacket(data, lazy, l)
}
