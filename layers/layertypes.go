// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"fmt"
	"github.com/gconnell/gopacket"
)

var (
	LayerTypeARP                  = gopacket.RegisterLayerType(10, "ARP", gopacket.DecoderFunc(decodeARP))
	LayerTypeCDP                  = gopacket.RegisterLayerType(11, "CDP", gopacket.DecoderFunc(decodeCDP))
	LayerTypeCTP                  = gopacket.RegisterLayerType(12, "CTP", gopacket.DecoderFunc(decodeCTP))
	LayerTypeCTPForwardData       = gopacket.RegisterLayerType(13, "CTPForwardData", gopacket.DecoderFunc(decodeCTPFromFunctionType))
	LayerTypeCTPReply             = gopacket.RegisterLayerType(14, "CTPReply", gopacket.DecoderFunc(decodeCTPReply))
	LayerTypeDot1Q                = gopacket.RegisterLayerType(15, "Dot1Q", gopacket.DecoderFunc(decodeDot1Q))
	LayerTypeEtherIP              = gopacket.RegisterLayerType(16, "EtherIP", gopacket.DecoderFunc(decodeEtherIP))
	LayerTypeEthernet             = gopacket.RegisterLayerType(17, "Ethernet", gopacket.DecoderFunc(decodeEthernet))
	LayerTypeGRE                  = gopacket.RegisterLayerType(18, "GRE", gopacket.DecoderFunc(decodeGRE))
	LayerTypeICMP                 = gopacket.RegisterLayerType(19, "ICMP", gopacket.DecoderFunc(decodeICMP))
	LayerTypeIPv4                 = gopacket.RegisterLayerType(20, "IPv4", gopacket.DecoderFunc(decodeIPv4))
	LayerTypeIPv6                 = gopacket.RegisterLayerType(21, "IPv6", gopacket.DecoderFunc(decodeIPv6))
	LayerTypeLLC                  = gopacket.RegisterLayerType(22, "LLC", gopacket.DecoderFunc(decodeLLC))
	LayerTypeSNAP                 = gopacket.RegisterLayerType(23, "SNAP", gopacket.DecoderFunc(decodeSNAP))
	LayerTypeMPLS                 = gopacket.RegisterLayerType(24, "MPLS", gopacket.DecoderFunc(decodeMPLS))
	LayerTypePPP                  = gopacket.RegisterLayerType(25, "PPP", gopacket.DecoderFunc(decodePPP))
	LayerTypePPPoE                = gopacket.RegisterLayerType(26, "PPPoE", gopacket.DecoderFunc(decodePPPoE))
	LayerTypeRUDP                 = gopacket.RegisterLayerType(27, "RUDP", gopacket.DecoderFunc(decodeRUDP))
	LayerTypeSCTP                 = gopacket.RegisterLayerType(28, "SCTP", gopacket.DecoderFunc(decodeSCTP))
	LayerTypeSCTPUnknownChunkType = gopacket.RegisterLayerType(29, "SCTPUnknownChunkType", gopacket.DecoderFunc(decodeWithSCTPChunkTypePrefix))
	LayerTypeSCTPData             = gopacket.RegisterLayerType(30, "SCTPData", gopacket.DecoderFunc(decodeWithSCTPChunkTypePrefix))
	LayerTypeSCTPInit             = gopacket.RegisterLayerType(31, "SCTPInit", gopacket.DecoderFunc(decodeWithSCTPChunkTypePrefix))
	LayerTypeSCTPSack             = gopacket.RegisterLayerType(32, "SCTPSack", gopacket.DecoderFunc(decodeWithSCTPChunkTypePrefix))
	LayerTypeSCTPHeartbeat        = gopacket.RegisterLayerType(33, "SCTPHeartbeat", gopacket.DecoderFunc(decodeWithSCTPChunkTypePrefix))
	LayerTypeSCTPError            = gopacket.RegisterLayerType(34, "SCTPError", gopacket.DecoderFunc(decodeWithSCTPChunkTypePrefix))
	LayerTypeSCTPShutdown         = gopacket.RegisterLayerType(35, "SCTPShutdown", gopacket.DecoderFunc(decodeWithSCTPChunkTypePrefix))
	LayerTypeSCTPShutdownAck      = gopacket.RegisterLayerType(36, "SCTPShutdownAck", gopacket.DecoderFunc(decodeWithSCTPChunkTypePrefix))
	LayerTypeSCTPCookieEcho       = gopacket.RegisterLayerType(37, "SCTPCookieEcho", gopacket.DecoderFunc(decodeWithSCTPChunkTypePrefix))
	LayerTypeSCTPEmptyLayer       = gopacket.RegisterLayerType(38, "SCTPEmptyLayer", gopacket.DecoderFunc(decodeWithSCTPChunkTypePrefix))
	LayerTypeTCP                  = gopacket.RegisterLayerType(39, "TCP", gopacket.DecoderFunc(decodeTCP))
	LayerTypeUDP                  = gopacket.RegisterLayerType(40, "UDP", gopacket.DecoderFunc(decodeUDP))
)
