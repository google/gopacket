// Copyright 2012 Google, gopacket.LayerTypeMetadata{Inc. All rights reserved}.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
)

var (
	LayerTypeARP                    = gopacket.RegisterLayerType(10, gopacket.LayerTypeMetadata{"ARP", gopacket.DecodeFunc(decodeARP)})
	LayerTypeCiscoDiscovery         = gopacket.RegisterLayerType(11, gopacket.LayerTypeMetadata{"CiscoDiscovery", gopacket.DecodeFunc(decodeCiscoDiscovery)})
	LayerTypeEthernetCTP            = gopacket.RegisterLayerType(12, gopacket.LayerTypeMetadata{"EthernetCTP", gopacket.DecodeFunc(decodeEthernetCTP)})
	LayerTypeEthernetCTPForwardData = gopacket.RegisterLayerType(13, gopacket.LayerTypeMetadata{"EthernetCTPForwardData", nil})
	LayerTypeEthernetCTPReply       = gopacket.RegisterLayerType(14, gopacket.LayerTypeMetadata{"EthernetCTPReply", nil})
	LayerTypeDot1Q                  = gopacket.RegisterLayerType(15, gopacket.LayerTypeMetadata{"Dot1Q", gopacket.DecodeFunc(decodeDot1Q)})
	LayerTypeEtherIP                = gopacket.RegisterLayerType(16, gopacket.LayerTypeMetadata{"EtherIP", gopacket.DecodeFunc(decodeEtherIP)})
	LayerTypeEthernet               = gopacket.RegisterLayerType(17, gopacket.LayerTypeMetadata{"Ethernet", gopacket.DecodeFunc(decodeEthernet)})
	LayerTypeGRE                    = gopacket.RegisterLayerType(18, gopacket.LayerTypeMetadata{"GRE", gopacket.DecodeFunc(decodeGRE)})
	LayerTypeICMPv4                 = gopacket.RegisterLayerType(19, gopacket.LayerTypeMetadata{"ICMPv4", gopacket.DecodeFunc(decodeICMPv4)})
	LayerTypeIPv4                   = gopacket.RegisterLayerType(20, gopacket.LayerTypeMetadata{"IPv4", gopacket.DecodeFunc(decodeIPv4)})
	LayerTypeIPv6                   = gopacket.RegisterLayerType(21, gopacket.LayerTypeMetadata{"IPv6", gopacket.DecodeFunc(decodeIPv6)})
	LayerTypeLLC                    = gopacket.RegisterLayerType(22, gopacket.LayerTypeMetadata{"LLC", gopacket.DecodeFunc(decodeLLC)})
	LayerTypeSNAP                   = gopacket.RegisterLayerType(23, gopacket.LayerTypeMetadata{"SNAP", gopacket.DecodeFunc(decodeSNAP)})
	LayerTypeMPLS                   = gopacket.RegisterLayerType(24, gopacket.LayerTypeMetadata{"MPLS", gopacket.DecodeFunc(decodeMPLS)})
	LayerTypePPP                    = gopacket.RegisterLayerType(25, gopacket.LayerTypeMetadata{"PPP", gopacket.DecodeFunc(decodePPP)})
	LayerTypePPPoE                  = gopacket.RegisterLayerType(26, gopacket.LayerTypeMetadata{"PPPoE", gopacket.DecodeFunc(decodePPPoE)})
	LayerTypeRUDP                   = gopacket.RegisterLayerType(27, gopacket.LayerTypeMetadata{"RUDP", gopacket.DecodeFunc(decodeRUDP)})
	LayerTypeSCTP                   = gopacket.RegisterLayerType(28, gopacket.LayerTypeMetadata{"SCTP", gopacket.DecodeFunc(decodeSCTP)})
	LayerTypeSCTPUnknownChunkType   = gopacket.RegisterLayerType(29, gopacket.LayerTypeMetadata{"SCTPUnknownChunkType", nil})
	LayerTypeSCTPData               = gopacket.RegisterLayerType(30, gopacket.LayerTypeMetadata{"SCTPData", nil})
	LayerTypeSCTPInit               = gopacket.RegisterLayerType(31, gopacket.LayerTypeMetadata{"SCTPInit", nil})
	LayerTypeSCTPSack               = gopacket.RegisterLayerType(32, gopacket.LayerTypeMetadata{"SCTPSack", nil})
	LayerTypeSCTPHeartbeat          = gopacket.RegisterLayerType(33, gopacket.LayerTypeMetadata{"SCTPHeartbeat", nil})
	LayerTypeSCTPError              = gopacket.RegisterLayerType(34, gopacket.LayerTypeMetadata{"SCTPError", nil})
	LayerTypeSCTPShutdown           = gopacket.RegisterLayerType(35, gopacket.LayerTypeMetadata{"SCTPShutdown", nil})
	LayerTypeSCTPShutdownAck        = gopacket.RegisterLayerType(36, gopacket.LayerTypeMetadata{"SCTPShutdownAck", nil})
	LayerTypeSCTPCookieEcho         = gopacket.RegisterLayerType(37, gopacket.LayerTypeMetadata{"SCTPCookieEcho", nil})
	LayerTypeSCTPEmptyLayer         = gopacket.RegisterLayerType(38, gopacket.LayerTypeMetadata{"SCTPEmptyLayer", nil})
	LayerTypeSCTPInitAck            = gopacket.RegisterLayerType(39, gopacket.LayerTypeMetadata{"LayerTypeSCTPInitAck", nil})
	LayerTypeSCTPHeartbeatAck       = gopacket.RegisterLayerType(40, gopacket.LayerTypeMetadata{"LayerTypeSCTPHeartbeatAck", nil})
	LayerTypeSCTPAbort              = gopacket.RegisterLayerType(41, gopacket.LayerTypeMetadata{"LayerTypeSCTPAbort", nil})
	LayerTypeSCTPShutdownComplete   = gopacket.RegisterLayerType(42, gopacket.LayerTypeMetadata{"LayerTypeSCTPShutdownComplete", nil})
	LayerTypeSCTPCookieAck          = gopacket.RegisterLayerType(43, gopacket.LayerTypeMetadata{"LayerTypeSCTPCookieAck", nil})
	LayerTypeTCP                    = gopacket.RegisterLayerType(44, gopacket.LayerTypeMetadata{"TCP", gopacket.DecodeFunc(decodeTCP)})
	LayerTypeUDP                    = gopacket.RegisterLayerType(45, gopacket.LayerTypeMetadata{"UDP", gopacket.DecodeFunc(decodeUDP)})
	LayerTypeIPv6HopByHop           = gopacket.RegisterLayerType(46, gopacket.LayerTypeMetadata{"IPv6HopByHop", gopacket.DecodeFunc(decodeIPv6HopByHop)})
	LayerTypeIPv6Routing            = gopacket.RegisterLayerType(47, gopacket.LayerTypeMetadata{"IPv6Routing", gopacket.DecodeFunc(decodeIPv6Routing)})
	LayerTypeIPv6Fragment           = gopacket.RegisterLayerType(48, gopacket.LayerTypeMetadata{"IPv6Fragment", gopacket.DecodeFunc(decodeIPv6Fragment)})
	LayerTypeIPv6Destination        = gopacket.RegisterLayerType(49, gopacket.LayerTypeMetadata{"IPv6Destination", gopacket.DecodeFunc(decodeIPv6Destination)})
	LayerTypeIPSecAH                = gopacket.RegisterLayerType(50, gopacket.LayerTypeMetadata{"IPSecAH", gopacket.DecodeFunc(decodeIPSecAH)})
	LayerTypeIPSecESP               = gopacket.RegisterLayerType(51, gopacket.LayerTypeMetadata{"IPSecESP", gopacket.DecodeFunc(decodeIPSecESP)})
	LayerTypeUDPLite                = gopacket.RegisterLayerType(52, gopacket.LayerTypeMetadata{"UDPLite", gopacket.DecodeFunc(decodeUDPLite)})
	LayerTypeFDDI                   = gopacket.RegisterLayerType(53, gopacket.LayerTypeMetadata{"FDDI", gopacket.DecodeFunc(decodeFDDI)})
	LayerTypeLoopback               = gopacket.RegisterLayerType(54, gopacket.LayerTypeMetadata{"Loopback", gopacket.DecodeFunc(decodeLoopback)})
	LayerTypeEAP                    = gopacket.RegisterLayerType(55, gopacket.LayerTypeMetadata{"EAP", gopacket.DecodeFunc(decodeEAP)})
	LayerTypeEAPOL                  = gopacket.RegisterLayerType(56, gopacket.LayerTypeMetadata{"EAPOL", gopacket.DecodeFunc(decodeEAPOL)})
	LayerTypeICMPv6                 = gopacket.RegisterLayerType(57, gopacket.LayerTypeMetadata{"ICMPv6", gopacket.DecodeFunc(decodeICMPv6)})
	LayerTypeLinkLayerDiscovery     = gopacket.RegisterLayerType(58, gopacket.LayerTypeMetadata{"LinkLayerDiscovery", gopacket.DecodeFunc(decodeLinkLayerDiscovery)})
	LayerTypeCiscoDiscoveryInfo     = gopacket.RegisterLayerType(59, gopacket.LayerTypeMetadata{"CiscoDiscoveryInfo", gopacket.DecodeFunc(decodeCiscoDiscoveryInfo)})
	LayerTypeLinkLayerDiscoveryInfo = gopacket.RegisterLayerType(60, gopacket.LayerTypeMetadata{"LinkLayerDiscoveryInfo", nil})
	LayerTypeNortelDiscovery        = gopacket.RegisterLayerType(61, gopacket.LayerTypeMetadata{"NortelDiscovery", gopacket.DecodeFunc(decodeNortelDiscovery)})
	LayerTypeIGMP                   = gopacket.RegisterLayerType(62, gopacket.LayerTypeMetadata{"IGMP", gopacket.DecodeFunc(decodeIGMP)})
)

var (
	// LayerClassIPNetwork contains TCP/IP network layer types.
	LayerClassIPNetwork = gopacket.NewLayerClass([]gopacket.LayerType{
		LayerTypeIPv4,
		LayerTypeIPv6,
	})
	// LayerClassIPTransport contains TCP/IP transport layer types.
	LayerClassIPTransport = gopacket.NewLayerClass([]gopacket.LayerType{
		LayerTypeTCP,
		LayerTypeUDP,
		LayerTypeSCTP,
	})
	// LayerClassIPControl contains TCP/IP control protocols.
	LayerClassIPControl = gopacket.NewLayerClass([]gopacket.LayerType{
		LayerTypeICMPv4,
		LayerTypeICMPv6,
	})
	// LayerClassSCTPChunk contains SCTP chunk types (not the top-level SCTP
	// layer).
	LayerClassSCTPChunk = gopacket.NewLayerClass([]gopacket.LayerType{
		LayerTypeSCTPUnknownChunkType,
		LayerTypeSCTPData,
		LayerTypeSCTPInit,
		LayerTypeSCTPSack,
		LayerTypeSCTPHeartbeat,
		LayerTypeSCTPError,
		LayerTypeSCTPShutdown,
		LayerTypeSCTPShutdownAck,
		LayerTypeSCTPCookieEcho,
		LayerTypeSCTPEmptyLayer,
		LayerTypeSCTPInitAck,
		LayerTypeSCTPHeartbeatAck,
		LayerTypeSCTPAbort,
		LayerTypeSCTPShutdownComplete,
		LayerTypeSCTPCookieAck,
	})
	// LayerClassIPv6Extension contains IPv6 extension headers.
	LayerClassIPv6Extension = gopacket.NewLayerClass([]gopacket.LayerType{
		LayerTypeIPv6HopByHop,
		LayerTypeIPv6Routing,
		LayerTypeIPv6Fragment,
		LayerTypeIPv6Destination,
	})
	LayerClassIPSec = gopacket.NewLayerClass([]gopacket.LayerType{
		LayerTypeIPSecAH,
		LayerTypeIPSecESP,
	})
)
