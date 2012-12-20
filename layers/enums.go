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
	EthernetTypeLLC                    EthernetType = 0
	EthernetTypeCiscoDiscoveryProtocol EthernetType = 0x2000
	EthernetTypeIPv4                   EthernetType = 0x0800
	EthernetTypeARP                    EthernetType = 0x0806
	EthernetTypeIPv6                   EthernetType = 0x86DD
	EthernetTypeDot1Q                  EthernetType = 0x8100
	EthernetTypePPPoEDiscovery         EthernetType = 0x8863
	EthernetTypePPPoESession           EthernetType = 0x8864
	EthernetTypeEthernetCTP            EthernetType = 0x9000
)

func (e EthernetType) Decode(data []byte) (out gopacket.DecodeResult, err error) {
	switch e {
	case EthernetTypeLLC:
		return decodeLLC(data)
	case EthernetTypeIPv4:
		return decodeIPv4(data)
	case EthernetTypeIPv6:
		return decodeIPv6(data)
	case EthernetTypeARP:
		return decodeARP(data)
	case EthernetTypeDot1Q:
		return decodeDot1Q(data)
	case EthernetTypePPPoEDiscovery, EthernetTypePPPoESession:
		return decodePPPoE(data)
	case EthernetTypeEthernetCTP:
		return decodeEthernetCTP(data)
	case EthernetTypeCiscoDiscoveryProtocol:
		return decodeCiscoDiscoveryProtocol(data)
	}
	err = fmt.Errorf("Unsupported ethernet type %v", e)
	return
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
	IPProtocolGRE          IPProtocol = 47
	IPProtocolIPIP         IPProtocol = 94
	IPProtocolEtherIP      IPProtocol = 97
	IPProtocolSCTP         IPProtocol = 132
)

func (ip IPProtocol) Decode(data []byte) (out gopacket.DecodeResult, err error) {
	switch ip {
	case IPProtocolTCP:
		return decodeTCP(data)
	case IPProtocolUDP:
		return decodeUDP(data)
	case IPProtocolICMP:
		return decodeICMP(data)
	case IPProtocolSCTP:
		return decodeSCTP(data)
	case IPProtocolIPv6:
		return decodeIPv6(data)
	case IPProtocolIPIP:
		return decodeIPv4(data)
	case IPProtocolEtherIP:
		return decodeEtherIP(data)
	case IPProtocolRUDP:
		return decodeRUDP(data)
	case IPProtocolGRE:
		return decodeGRE(data)
	case IPProtocolIPv6HopByHop:
		return decodeIPv6HopByHop(data)
	case IPProtocolIPv6Routing:
		return decodeIPv6Routing(data)
	}
	err = fmt.Errorf("Unsupported IP protocol %v", ip)
	return
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

func (l LinkType) Decode(data []byte) (out gopacket.DecodeResult, err error) {
	switch l {
	case LinkTypeEthernet:
		return decodeEthernet(data)
	case LinkTypePPP:
		return decodePPP(data)
	}
	err = fmt.Errorf("Unsupported link-layer type %v", l)
	return
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
func (p PPPoECode) Decode(data []byte) (_ gopacket.DecodeResult, err error) {
	switch p {
	case PPPoECodeSession:
		return decodePPP(data)
	}
	err = fmt.Errorf("Cannot currently handle PPPoE error code %v", p)
	return
}

// PPPType is an enumeration of PPP type values, and acts as a decoder for any
// type it supports.
type PPPType uint16

const (
	PPPTypeIPv4 PPPType = 0x0021
	PPPTypeIPv6 PPPType = 0x0057
)

func (p PPPType) Decode(data []byte) (out gopacket.DecodeResult, err error) {
	switch p {
	case PPPTypeIPv4:
		return decodeIPv4(data)
	case PPPTypeIPv6:
		return decodeIPv6(data)
	}
	err = fmt.Errorf("Unsupported PPP type %v", p)
	return
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

func (s SCTPChunkType) Decode(data []byte) (_ gopacket.DecodeResult, err error) {
	switch s {
	case SCTPChunkTypeData:
		return decodeSCTPData(data)
	case SCTPChunkTypeInit, SCTPChunkTypeInitAck:
		return decodeSCTPInit(data)
	case SCTPChunkTypeSack:
		return decodeSCTPSack(data)
	case SCTPChunkTypeHeartbeat, SCTPChunkTypeHeartbeatAck:
		return decodeSCTPHeartbeat(data)
	case SCTPChunkTypeAbort, SCTPChunkTypeError:
		return decodeSCTPError(data)
	case SCTPChunkTypeShutdown:
		return decodeSCTPShutdown(data)
	case SCTPChunkTypeShutdownAck:
		return decodeSCTPShutdownAck(data)
	case SCTPChunkTypeCookieEcho:
		return decodeSCTPCookieEcho(data)
	case SCTPChunkTypeCookieAck, SCTPChunkTypeShutdownComplete:
		return decodeSCTPEmptyLayer(data)
	}
	err = fmt.Errorf("Unable to decode SCTP chunk type %v", s)
	return
}
