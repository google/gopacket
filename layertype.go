// Copyright (c) 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"strconv"
)

// LayerType is a unique identifier for each type of layer.  This enumeration
// does not match with any externally available numbering scheme... it's solely
// usable/useful within this library as a means for requesting layer types
// (see Packet.Layer) and determining which types of layers have been decoded.
// A LayerType corresponds 1:1 to a struct type.
type LayerType uint

// When you add a new type here, make sure to also update the LayerClass objects
// below.
const (
	LayerTypePayload LayerType = iota
	LayerTypeDecodeFailure
	LayerTypeEthernet
	LayerTypeEtherIP
	LayerTypePPP
	LayerTypeGRE
	LayerTypeIPv4
	LayerTypeIPv6
	LayerTypeTCP
	LayerTypeUDP
	LayerTypeRUDP
	LayerTypeSCTP
	// <sctp chunk layers>
	LayerTypeSCTPData
	LayerTypeSCTPInit
	LayerTypeSCTPInitAck
	LayerTypeSCTPSack
	LayerTypeSCTPHeartbeat
	LayerTypeSCTPHeartbeatAck
	LayerTypeSCTPAbort
	LayerTypeSCTPError
	LayerTypeSCTPShutdown
	LayerTypeSCTPShutdownAck
	LayerTypeSCTPShutdownComplete
	LayerTypeSCTPCookieEcho
	LayerTypeSCTPCookieAck
	// </sctp chunk layers>
	LayerTypeSCTPUnknownChunkType
	LayerTypeICMP
	LayerTypeDot1Q
	LayerTypeARP
	LayerTypeMPLS
	LayerTypePPPoE
	// MaximumLayerType should always be the largest layertype in gopacket.  Any
	// layer types above this are assumed to be user layer types created outside
	// of gopacket.
	MaximumLayerType
)

func (l LayerType) String() string {
	switch l {
	case LayerTypePayload:
		return "Payload"
	case LayerTypeDecodeFailure:
		return "DecodeFailure"
	case LayerTypeEthernet:
		return "Ethernet"
	case LayerTypeEtherIP:
		return "EtherIP"
	case LayerTypePPP:
		return "PPP"
	case LayerTypeGRE:
		return "GRE"
	case LayerTypeIPv4:
		return "IPv4"
	case LayerTypeIPv6:
		return "IPv6"
	case LayerTypeTCP:
		return "TCP"
	case LayerTypeUDP:
		return "UDP"
	case LayerTypeRUDP:
		return "RUDP"
	case LayerTypeSCTP:
		return "SCTP"
	case LayerTypeSCTPData:
		return "SCTPData"
	case LayerTypeSCTPInit:
		return "SCTPInit"
	case LayerTypeSCTPInitAck:
		return "SCTPInitAck"
	case LayerTypeSCTPSack:
		return "SCTPSack"
	case LayerTypeSCTPHeartbeat:
		return "SCTPHeartbeat"
	case LayerTypeSCTPHeartbeatAck:
		return "SCTPHeartbeatAck"
	case LayerTypeSCTPAbort:
		return "SCTPAbort"
	case LayerTypeSCTPError:
		return "SCTPError"
	case LayerTypeSCTPShutdown:
		return "SCTPShutdown"
	case LayerTypeSCTPShutdownAck:
		return "SCTPShutdownAck"
	case LayerTypeSCTPShutdownComplete:
		return "SCTPShutdownComplete"
	case LayerTypeSCTPCookieEcho:
		return "SCTPCookieEcho"
	case LayerTypeSCTPCookieAck:
		return "SCTPCookieAck"
	case LayerTypeSCTPUnknownChunkType:
		return "SCTPUnknownChunkType"
	case LayerTypeICMP:
		return "ICMP"
	case LayerTypeDot1Q:
		return "Dot1Q"
	case LayerTypeARP:
		return "ARP"
	}
	return strconv.Itoa(int(l))
}

// LayerClassLink contains all link layers
var LayerClassLink = NewLayerClass([]LayerType{LayerTypePPP, LayerTypeEthernet})

// LayerClassNetwork contains all network layers
var LayerClassNetwork = NewLayerClass([]LayerType{LayerTypeIPv4, LayerTypeIPv6})

// LayerClassTransport contains all transport layers
var LayerClassTransport = NewLayerClass([]LayerType{
	LayerTypeTCP,
	LayerTypeUDP,
	LayerTypeRUDP,
})

// LayerClassApplication contains all application layers
var LayerClassApplication = NewLayerClass([]LayerType{LayerTypePayload})

// LayerClassError contains all error layers
var LayerClassError = NewLayerClass([]LayerType{LayerTypeDecodeFailure, LayerTypeSCTPUnknownChunkType})

// LayerClassIP contains all IP layers
var LayerClassIP = NewLayerClass([]LayerType{LayerTypeIPv4, LayerTypeIPv6})

// LayerClassSCTPChunk contains all SCTP chunk type layers
var LayerClassSCTPChunk = NewLayerClass([]LayerType{
	LayerTypeSCTPData,
	LayerTypeSCTPInit,
	LayerTypeSCTPInitAck,
	LayerTypeSCTPSack,
	LayerTypeSCTPHeartbeat,
	LayerTypeSCTPHeartbeatAck,
	LayerTypeSCTPAbort,
	LayerTypeSCTPError,
	LayerTypeSCTPShutdown,
	LayerTypeSCTPShutdownAck,
	LayerTypeSCTPShutdownComplete,
	LayerTypeSCTPCookieEcho,
	LayerTypeSCTPCookieAck,
	LayerTypeSCTPUnknownChunkType,
})
