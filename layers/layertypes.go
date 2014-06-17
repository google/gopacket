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
	LayerTypePFLog                  = gopacket.RegisterLayerType(63, gopacket.LayerTypeMetadata{"PFLog", gopacket.DecodeFunc(decodePFLog)})
	LayerTypeRadiotap               = gopacket.RegisterLayerType(64, gopacket.LayerTypeMetadata{"Radiotap", gopacket.DecodeFunc(decodeRadiotap)})
	LayerTypeDot11                  = gopacket.RegisterLayerType(65, gopacket.LayerTypeMetadata{"Dot11", gopacket.DecodeFunc(decodeDot11)})
	LayerTypeDot11ControlFrame      = gopacket.RegisterLayerType(66, gopacket.LayerTypeMetadata{"Dot11ControlFrame", gopacket.DecodeFunc(decodeDot11ControlFrame)})
	LayerTypeDot11DataFrame         = gopacket.RegisterLayerType(67, gopacket.LayerTypeMetadata{"Dot11DataFrame", gopacket.DecodeFunc(decodeDot11DataFrame)})
	LayerTypeDot11DataCfAck         = gopacket.RegisterLayerType(68, gopacket.LayerTypeMetadata{"Dot11DataCfAck", gopacket.DecodeFunc(decodeDot11DataCfAck)})
	LayerTypeDot11DataCfPoll        = gopacket.RegisterLayerType(69, gopacket.LayerTypeMetadata{"Dot11DataCfPoll", gopacket.DecodeFunc(decodeDot11DataCfPoll)})
	LayerTypeDot11DataCfAckPoll     = gopacket.RegisterLayerType(70, gopacket.LayerTypeMetadata{"Dot11DataCfAckPoll", gopacket.DecodeFunc(decodeDot11DataCfAckPoll)})
	LayerTypeDot11DataNull          = gopacket.RegisterLayerType(71, gopacket.LayerTypeMetadata{"Dot11DataNull", gopacket.DecodeFunc(decodeDot11DataNull)})
	LayerTypeDot11DataCfAckNoData   = gopacket.RegisterLayerType(72, gopacket.LayerTypeMetadata{"Dot11DataCfAckNoData", gopacket.DecodeFunc(decodeDot11DataCfAckNoData)})
	LayerTypeDot11DataCfPollNoData          = gopacket.RegisterLayerType(73, gopacket.LayerTypeMetadata{"Dot11DataCfPollNoData", gopacket.DecodeFunc(decodeDot11DataCfPollNoData)})
	LayerTypeDot11DataCfAckPollNoData       = gopacket.RegisterLayerType(74, gopacket.LayerTypeMetadata{"Dot11DataCfAckPollNoData", gopacket.DecodeFunc(decodeDot11DataCfAckPollNoData)})
	LayerTypeDot11DataQosData               = gopacket.RegisterLayerType(75, gopacket.LayerTypeMetadata{"Dot11DataQosData", gopacket.DecodeFunc(decodeDot11DataQosData)})
	LayerTypeDot11DataQosDataCfAck          = gopacket.RegisterLayerType(76, gopacket.LayerTypeMetadata{"Dot11DataQosDataCfAck", gopacket.DecodeFunc(decodeDot11DataQosDataCfAck)})
	LayerTypeDot11DataQosDataCfPoll         = gopacket.RegisterLayerType(77, gopacket.LayerTypeMetadata{"Dot11DataQosDataCfPoll", gopacket.DecodeFunc(decodeDot11DataQosDataCfPoll)})
	LayerTypeDot11DataQosDataCfAckPoll      = gopacket.RegisterLayerType(78, gopacket.LayerTypeMetadata{"Dot11DataQosDataCfAckPoll", gopacket.DecodeFunc(decodeDot11DataQosDataCfAckPoll)})
	LayerTypeDot11DataQosNull               = gopacket.RegisterLayerType(79, gopacket.LayerTypeMetadata{"Dot11DataQosNull", gopacket.DecodeFunc(decodeDot11DataQosNull)})
	LayerTypeDot11DataQosCfPollNoData       = gopacket.RegisterLayerType(80, gopacket.LayerTypeMetadata{"Dot11DataQosCfPollNoData", gopacket.DecodeFunc(decodeDot11DataQosCfPollNoData)})
	LayerTypeDot11DataQosCfAckPollNoData    = gopacket.RegisterLayerType(81, gopacket.LayerTypeMetadata{"Dot11DataQosCfAckPollNoData", gopacket.DecodeFunc(decodeDot11DataQosCfAckPollNoData)})
	LayerTypeDot11InformationElement        = gopacket.RegisterLayerType(82, gopacket.LayerTypeMetadata{"Dot11InformationElement", gopacket.DecodeFunc(decodeDot11InformationElement)})
	LayerTypeDot11ControlClearToSend      = gopacket.RegisterLayerType(83, gopacket.LayerTypeMetadata{"Dot11ControlClearToSend", gopacket.DecodeFunc(decodeDot11ControlClearToSend)})
	LayerTypeDot11ControlRequestToSend      = gopacket.RegisterLayerType(84, gopacket.LayerTypeMetadata{"Dot11ControlRequestToSend", gopacket.DecodeFunc(decodeDot11ControlRequestToSend)})
	LayerTypeDot11ControlBlockAckReq      = gopacket.RegisterLayerType(85, gopacket.LayerTypeMetadata{"Dot11ControlBlockAckReq", gopacket.DecodeFunc(decodeDot11ControlBlockAckReq)})
	LayerTypeDot11ControlBlockAck      = gopacket.RegisterLayerType(86, gopacket.LayerTypeMetadata{"Dot11ControlBlockAck", gopacket.DecodeFunc(decodeDot11ControlBlockAck)})
	LayerTypeDot11ControlPowersavePoll      = gopacket.RegisterLayerType(87, gopacket.LayerTypeMetadata{"Dot11ControlPowersavePoll", gopacket.DecodeFunc(decodeDot11ControlPowersavePoll)})
	LayerTypeDot11ControlAcknowledgement      = gopacket.RegisterLayerType(88, gopacket.LayerTypeMetadata{"Dot11ControlAcknowledgement", gopacket.DecodeFunc(decodeDot11ControlAcknowledgement)})
	LayerTypeDot11ControlContentionFreePeriodEnd      = gopacket.RegisterLayerType(89, gopacket.LayerTypeMetadata{"Dot11ControlContentionFreePeriodEnd", gopacket.DecodeFunc(decodeDot11ControlContentionFreePeriodEnd)})
	LayerTypeDot11ControlContentionFreePeriodEndAck      = gopacket.RegisterLayerType(90, gopacket.LayerTypeMetadata{"Dot11ControlContentionFreePeriodEndAck", gopacket.DecodeFunc(decodeDot11ControlContentionFreePeriodEndAck)})
	LayerTypeDot11MgmtAssocReq      = gopacket.RegisterLayerType(91, gopacket.LayerTypeMetadata{"Dot11MgmtAssocReq", gopacket.DecodeFunc(decodeDot11MgmtAssocReq)})
	LayerTypeDot11MgmtAssocResp      = gopacket.RegisterLayerType(92, gopacket.LayerTypeMetadata{"Dot11MgmtAssocResp", gopacket.DecodeFunc(decodeDot11MgmtAssocResp)})
	LayerTypeDot11MgmtReassocReq      = gopacket.RegisterLayerType(93, gopacket.LayerTypeMetadata{"Dot11MgmtReassocReq", gopacket.DecodeFunc(decodeDot11MgmtReassocReq)})
	LayerTypeDot11MgmtReassocResp      = gopacket.RegisterLayerType(94, gopacket.LayerTypeMetadata{"Dot11MgmtReassocResp", gopacket.DecodeFunc(decodeDot11MgmtReassocResp)})
	LayerTypeDot11MgmtProbeReq      = gopacket.RegisterLayerType(95, gopacket.LayerTypeMetadata{"Dot11MgmtProbeReq", gopacket.DecodeFunc(decodeDot11MgmtProbeReq)})
	LayerTypeDot11MgmtProbeResp      = gopacket.RegisterLayerType(96, gopacket.LayerTypeMetadata{"Dot11MgmtProbeResp", gopacket.DecodeFunc(decodeDot11MgmtProbeResp)})
	LayerTypeDot11MgmtMeasurementPilot      = gopacket.RegisterLayerType(97, gopacket.LayerTypeMetadata{"Dot11MgmtMeasurementPilot", gopacket.DecodeFunc(decodeDot11MgmtMeasurementPilot)})
	LayerTypeDot11MgmtBeacon      = gopacket.RegisterLayerType(98, gopacket.LayerTypeMetadata{"Dot11MgmtBeacon", gopacket.DecodeFunc(decodeDot11MgmtBeacon)})
	LayerTypeDot11MgmtATIM      = gopacket.RegisterLayerType(99, gopacket.LayerTypeMetadata{"Dot11MgmtATIM", gopacket.DecodeFunc(decodeDot11MgmtATIM)})
	LayerTypeDot11MgmtDisassociation      = gopacket.RegisterLayerType(100, gopacket.LayerTypeMetadata{"Dot11MgmtDisassociation", gopacket.DecodeFunc(decodeDot11MgmtDisassociation)})
	LayerTypeDot11MgmtAuthentication      = gopacket.RegisterLayerType(101, gopacket.LayerTypeMetadata{"Dot11MgmtAuthentication", gopacket.DecodeFunc(decodeDot11MgmtAuthentication)})
	LayerTypeDot11MgmtDeauthentication      = gopacket.RegisterLayerType(102, gopacket.LayerTypeMetadata{"Dot11MgmtDeauthentication", gopacket.DecodeFunc(decodeDot11MgmtDeauthentication)})
	LayerTypeDot11MgmtAction      = gopacket.RegisterLayerType(103, gopacket.LayerTypeMetadata{"Dot11MgmtAction", gopacket.DecodeFunc(decodeDot11MgmtAction)})
	LayerTypeDot11MgmtActionNoAck      = gopacket.RegisterLayerType(104, gopacket.LayerTypeMetadata{"Dot11MgmtActionNoAck", gopacket.DecodeFunc(decodeDot11MgmtActionNoAck)})
	LayerTypeDot11MgmtArubaWlan      = gopacket.RegisterLayerType(105, gopacket.LayerTypeMetadata{"Dot11MgmtArubaWlan", gopacket.DecodeFunc(decodeDot11MgmtArubaWlan)})
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
