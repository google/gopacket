// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package layers

import (
	"fmt"
	"github.com/gconnell/gopacket"
)

// EthernetType is an enumeration of ethernet type values, and acts as a decoder
// for any type it supports.
type EthernetType uint16

const (
	// EthernetTypeLLC is not an actual ethernet type.  It is instead a
	// placeholder we use in Ethernet frames that use the 802.3 standard of
	// srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
	EthernetTypeLLC            EthernetType = 0
	EthernetTypeCiscoDiscovery EthernetType = 0x2000
	EthernetTypeIPv4           EthernetType = 0x0800
	EthernetTypeARP            EthernetType = 0x0806
	EthernetTypeIPv6           EthernetType = 0x86DD
	EthernetTypeDot1Q          EthernetType = 0x8100
	EthernetTypePPPoEDiscovery EthernetType = 0x8863
	EthernetTypePPPoESession   EthernetType = 0x8864
	EthernetTypeEthernetCTP    EthernetType = 0x9000
)

func (e EthernetType) Decode(data []byte, p gopacket.PacketBuilder) error {
	switch e {
	case EthernetTypeLLC:
		return decodeLLC(data, p)
	case EthernetTypeIPv4:
		return decodeIPv4(data, p)
	case EthernetTypeIPv6:
		return decodeIPv6(data, p)
	case EthernetTypeARP:
		return decodeARP(data, p)
	case EthernetTypeDot1Q:
		return decodeDot1Q(data, p)
	case EthernetTypePPPoEDiscovery, EthernetTypePPPoESession:
		return decodePPPoE(data, p)
	case EthernetTypeEthernetCTP:
		return decodeEthernetCTP(data, p)
	case EthernetTypeCiscoDiscovery:
		return decodeCiscoDiscovery(data, p)
	}
	return fmt.Errorf("Unsupported ethernet type %v", e)
}

// IPProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
type IPProtocol uint8

const (
	IPProtocolIPv6HopByHop IPProtocol = 0
	IPProtocolICMP         IPProtocol = 1
	IPProtocolTCP          IPProtocol = 6
	IPProtocolUDP          IPProtocol = 17
	IPProtocolRUDP         IPProtocol = 27
	IPProtocolIPv6         IPProtocol = 41
	IPProtocolIPv6Routing  IPProtocol = 43
	IPProtocolIPv6Fragment IPProtocol = 44
	IPProtocolGRE          IPProtocol = 47
	IPProtocolESP          IPProtocol = 50
	IPProtocolAH           IPProtocol = 51
	IPProtocolNoNextHeader IPProtocol = 59
	IPProtocolIPIP         IPProtocol = 94
	IPProtocolEtherIP      IPProtocol = 97
	IPProtocolSCTP         IPProtocol = 132
)

func (ip IPProtocol) Decode(data []byte, p gopacket.PacketBuilder) error {
	switch ip {
	case IPProtocolTCP:
		return decodeTCP(data, p)
	case IPProtocolUDP:
		return decodeUDP(data, p)
	case IPProtocolICMP:
		return decodeICMP(data, p)
	case IPProtocolSCTP:
		return decodeSCTP(data, p)
	case IPProtocolIPv6:
		return decodeIPv6(data, p)
	case IPProtocolIPIP:
		return decodeIPv4(data, p)
	case IPProtocolEtherIP:
		return decodeEtherIP(data, p)
	case IPProtocolRUDP:
		return decodeRUDP(data, p)
	case IPProtocolGRE:
		return decodeGRE(data, p)
	case IPProtocolIPv6HopByHop:
		return decodeIPv6HopByHop(data, p)
	case IPProtocolIPv6Routing:
		return decodeIPv6Routing(data, p)
	case IPProtocolIPv6Fragment:
		return decodeIPv6Fragment(data, p)
	case IPProtocolAH:
		return decodeIPSecAH(data, p)
	case IPProtocolESP:
		return decodeIPSecESP(data, p)
	case IPProtocolNoNextHeader:
		return fmt.Errorf("NoNextHeader found with %d bytes remaining to decode", len(data))
	}
	return fmt.Errorf("Unsupported IP protocol %v", ip)
}

// LinkType is an enumeration of link types, and acts as a decoder for any
// link type it supports.
type LinkType int

const (
	// According to pcap-linktype(7).
	LinkTypeNull           LinkType = 0
	LinkTypeEthernet       LinkType = 1
	LinkTypeTokenRing      LinkType = 6
	LinkTypeArcNet         LinkType = 7
	LinkTypeSLIP           LinkType = 8
	LinkTypePPP            LinkType = 9
	LinkTypeFDDI           LinkType = 10
	LinkTypeATM_RFC1483    LinkType = 100
	LinkTypeRaw            LinkType = 101
	LinkTypePPP_HDLC       LinkType = 50
	LinkTypePPPEthernet    LinkType = 51
	LinkTypeC_HDLC         LinkType = 104
	LinkTypeIEEE802_11     LinkType = 105
	LinkTypeFRelay         LinkType = 107
	LinkTypeLoop           LinkType = 108
	LinkTypeLinuxSLL       LinkType = 113
	LinkTypeLTalk          LinkType = 104
	LinkTypePFLog          LinkType = 117
	LinkTypePrismHeader    LinkType = 119
	LinkTypeIPOverFC       LinkType = 122
	LinkTypeSunATM         LinkType = 123
	LinkTypeIEEE80211Radio LinkType = 127
	LinkTypeARCNetLinux    LinkType = 129
	LinkTypeLinuxIRDA      LinkType = 144
	LinkTypeLinuxLAPD      LinkType = 177
)

func (l LinkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	switch l {
	case LinkTypeEthernet:
		return decodeEthernet(data, p)
	case LinkTypePPP:
		return decodePPP(data, p)
	}
	return fmt.Errorf("Unsupported link-layer type %v", l)
}

// PPPoECode is the PPPoE code enum, taken from http://tools.ietf.org/html/rfc2516
type PPPoECode int

const (
	PPPoECodePADI    PPPoECode = 0x09
	PPPoECodePADO    PPPoECode = 0x07
	PPPoECodePADR    PPPoECode = 0x19
	PPPoECodePADS    PPPoECode = 0x65
	PPPoECodePADT    PPPoECode = 0xA7
	PPPoECodeSession PPPoECode = 0x00
)

// Decode decodes a PPPoE payload, based on the PPPoECode.
func (pc PPPoECode) Decode(data []byte, p gopacket.PacketBuilder) error {
	switch pc {
	case PPPoECodeSession:
		return decodePPP(data, p)
	}
	return fmt.Errorf("Cannot currently handle PPPoE error code %v", pc)
}

// PPPType is an enumeration of PPP type values, and acts as a decoder for any
// type it supports.
type PPPType uint16

const (
	PPPTypeIPv4 PPPType = 0x0021
	PPPTypeIPv6 PPPType = 0x0057
)

func (pt PPPType) Decode(data []byte, p gopacket.PacketBuilder) error {
	switch pt {
	case PPPTypeIPv4:
		return decodeIPv4(data, p)
	case PPPTypeIPv6:
		return decodeIPv6(data, p)
	}
	return fmt.Errorf("Unsupported PPP type %v", pt)
}

// SCTPChunkType is an enumeration of chunk types inside SCTP packets.
type SCTPChunkType uint8

const (
	SCTPChunkTypeData             SCTPChunkType = 0
	SCTPChunkTypeInit             SCTPChunkType = 1
	SCTPChunkTypeInitAck          SCTPChunkType = 2
	SCTPChunkTypeSack             SCTPChunkType = 3
	SCTPChunkTypeHeartbeat        SCTPChunkType = 4
	SCTPChunkTypeHeartbeatAck     SCTPChunkType = 5
	SCTPChunkTypeAbort            SCTPChunkType = 6
	SCTPChunkTypeShutdown         SCTPChunkType = 7
	SCTPChunkTypeShutdownAck      SCTPChunkType = 8
	SCTPChunkTypeError            SCTPChunkType = 9
	SCTPChunkTypeCookieEcho       SCTPChunkType = 10
	SCTPChunkTypeCookieAck        SCTPChunkType = 11
	SCTPChunkTypeShutdownComplete SCTPChunkType = 14
)

func (s SCTPChunkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	switch s {
	case SCTPChunkTypeData:
		return decodeSCTPData(data, p)
	case SCTPChunkTypeInit, SCTPChunkTypeInitAck:
		return decodeSCTPInit(data, p)
	case SCTPChunkTypeSack:
		return decodeSCTPSack(data, p)
	case SCTPChunkTypeHeartbeat, SCTPChunkTypeHeartbeatAck:
		return decodeSCTPHeartbeat(data, p)
	case SCTPChunkTypeAbort, SCTPChunkTypeError:
		return decodeSCTPError(data, p)
	case SCTPChunkTypeShutdown:
		return decodeSCTPShutdown(data, p)
	case SCTPChunkTypeShutdownAck:
		return decodeSCTPShutdownAck(data, p)
	case SCTPChunkTypeCookieEcho:
		return decodeSCTPCookieEcho(data, p)
	case SCTPChunkTypeCookieAck, SCTPChunkTypeShutdownComplete:
		return decodeSCTPEmptyLayer(data, p)
	}
	return fmt.Errorf("Unable to decode SCTP chunk type %v", s)
}
