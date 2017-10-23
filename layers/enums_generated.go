// Copyright 2012 Google, Inc. All rights reserved.

package layers

// Created by gen2.go, don't edit manually
// Generated at 2017-10-23 10:13:41.708259103 -0600 MDT m=+0.001033329

import (
	"fmt"

	"github.com/google/gopacket"
)

func init() {
	initUnknownTypesForLinkType()
	initUnknownTypesForEthernetType()
	initUnknownTypesForPPPType()
	initUnknownTypesForIPProtocol()
	initUnknownTypesForSCTPChunkType()
	initUnknownTypesForPPPoECode()
	initUnknownTypesForFDDIFrameControl()
	initUnknownTypesForEAPOLType()
	initUnknownTypesForProtocolFamily()
	initUnknownTypesForDot11Type()
	initUnknownTypesForUSBTransportType()
	initActualTypeData()
}

func (a LinkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return LinkTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a LinkType) String() string {
	return LinkTypeMetadata[a].Name
}
func (a LinkType) LayerType() gopacket.LayerType {
	return LinkTypeMetadata[a].LayerType
}

type errorDecoderForLinkType int

func (a *errorDecoderForLinkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}
func (a *errorDecoderForLinkType) Error() string {
	return fmt.Sprintf("Unable to decode LinkType %d", int(*a))
}

var errorDecodersForLinkType [256]errorDecoderForLinkType
var LinkTypeMetadata [256]EnumMetadata

func initUnknownTypesForLinkType() {
	for i := 0; i < 256; i++ {
		errorDecodersForLinkType[i] = errorDecoderForLinkType(i)
		LinkTypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForLinkType[i],
			Name:       "UnknownLinkType",
		}
	}
}

func (a EthernetType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return EthernetTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a EthernetType) String() string {
	return EthernetTypeMetadata[a].Name
}
func (a EthernetType) LayerType() gopacket.LayerType {
	return EthernetTypeMetadata[a].LayerType
}

type errorDecoderForEthernetType int

func (a *errorDecoderForEthernetType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}
func (a *errorDecoderForEthernetType) Error() string {
	return fmt.Sprintf("Unable to decode EthernetType %d", int(*a))
}

var errorDecodersForEthernetType [65536]errorDecoderForEthernetType
var EthernetTypeMetadata [65536]EnumMetadata

func initUnknownTypesForEthernetType() {
	for i := 0; i < 65536; i++ {
		errorDecodersForEthernetType[i] = errorDecoderForEthernetType(i)
		EthernetTypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForEthernetType[i],
			Name:       "UnknownEthernetType",
		}
	}
}

func (a PPPType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return PPPTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a PPPType) String() string {
	return PPPTypeMetadata[a].Name
}
func (a PPPType) LayerType() gopacket.LayerType {
	return PPPTypeMetadata[a].LayerType
}

type errorDecoderForPPPType int

func (a *errorDecoderForPPPType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}
func (a *errorDecoderForPPPType) Error() string {
	return fmt.Sprintf("Unable to decode PPPType %d", int(*a))
}

var errorDecodersForPPPType [65536]errorDecoderForPPPType
var PPPTypeMetadata [65536]EnumMetadata

func initUnknownTypesForPPPType() {
	for i := 0; i < 65536; i++ {
		errorDecodersForPPPType[i] = errorDecoderForPPPType(i)
		PPPTypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForPPPType[i],
			Name:       "UnknownPPPType",
		}
	}
}

func (a IPProtocol) Decode(data []byte, p gopacket.PacketBuilder) error {
	return IPProtocolMetadata[a].DecodeWith.Decode(data, p)
}
func (a IPProtocol) String() string {
	return IPProtocolMetadata[a].Name
}
func (a IPProtocol) LayerType() gopacket.LayerType {
	return IPProtocolMetadata[a].LayerType
}

type errorDecoderForIPProtocol int

func (a *errorDecoderForIPProtocol) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}
func (a *errorDecoderForIPProtocol) Error() string {
	return fmt.Sprintf("Unable to decode IPProtocol %d", int(*a))
}

var errorDecodersForIPProtocol [256]errorDecoderForIPProtocol
var IPProtocolMetadata [256]EnumMetadata

func initUnknownTypesForIPProtocol() {
	for i := 0; i < 256; i++ {
		errorDecodersForIPProtocol[i] = errorDecoderForIPProtocol(i)
		IPProtocolMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForIPProtocol[i],
			Name:       "UnknownIPProtocol",
		}
	}
}

func (a SCTPChunkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return SCTPChunkTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a SCTPChunkType) String() string {
	return SCTPChunkTypeMetadata[a].Name
}
func (a SCTPChunkType) LayerType() gopacket.LayerType {
	return SCTPChunkTypeMetadata[a].LayerType
}

type errorDecoderForSCTPChunkType int

func (a *errorDecoderForSCTPChunkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}
func (a *errorDecoderForSCTPChunkType) Error() string {
	return fmt.Sprintf("Unable to decode SCTPChunkType %d", int(*a))
}

var errorDecodersForSCTPChunkType [256]errorDecoderForSCTPChunkType
var SCTPChunkTypeMetadata [256]EnumMetadata

func initUnknownTypesForSCTPChunkType() {
	for i := 0; i < 256; i++ {
		errorDecodersForSCTPChunkType[i] = errorDecoderForSCTPChunkType(i)
		SCTPChunkTypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForSCTPChunkType[i],
			Name:       "UnknownSCTPChunkType",
		}
	}
}

func (a PPPoECode) Decode(data []byte, p gopacket.PacketBuilder) error {
	return PPPoECodeMetadata[a].DecodeWith.Decode(data, p)
}
func (a PPPoECode) String() string {
	return PPPoECodeMetadata[a].Name
}
func (a PPPoECode) LayerType() gopacket.LayerType {
	return PPPoECodeMetadata[a].LayerType
}

type errorDecoderForPPPoECode int

func (a *errorDecoderForPPPoECode) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}
func (a *errorDecoderForPPPoECode) Error() string {
	return fmt.Sprintf("Unable to decode PPPoECode %d", int(*a))
}

var errorDecodersForPPPoECode [256]errorDecoderForPPPoECode
var PPPoECodeMetadata [256]EnumMetadata

func initUnknownTypesForPPPoECode() {
	for i := 0; i < 256; i++ {
		errorDecodersForPPPoECode[i] = errorDecoderForPPPoECode(i)
		PPPoECodeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForPPPoECode[i],
			Name:       "UnknownPPPoECode",
		}
	}
}

func (a FDDIFrameControl) Decode(data []byte, p gopacket.PacketBuilder) error {
	return FDDIFrameControlMetadata[a].DecodeWith.Decode(data, p)
}
func (a FDDIFrameControl) String() string {
	return FDDIFrameControlMetadata[a].Name
}
func (a FDDIFrameControl) LayerType() gopacket.LayerType {
	return FDDIFrameControlMetadata[a].LayerType
}

type errorDecoderForFDDIFrameControl int

func (a *errorDecoderForFDDIFrameControl) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}
func (a *errorDecoderForFDDIFrameControl) Error() string {
	return fmt.Sprintf("Unable to decode FDDIFrameControl %d", int(*a))
}

var errorDecodersForFDDIFrameControl [256]errorDecoderForFDDIFrameControl
var FDDIFrameControlMetadata [256]EnumMetadata

func initUnknownTypesForFDDIFrameControl() {
	for i := 0; i < 256; i++ {
		errorDecodersForFDDIFrameControl[i] = errorDecoderForFDDIFrameControl(i)
		FDDIFrameControlMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForFDDIFrameControl[i],
			Name:       "UnknownFDDIFrameControl",
		}
	}
}

func (a EAPOLType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return EAPOLTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a EAPOLType) String() string {
	return EAPOLTypeMetadata[a].Name
}
func (a EAPOLType) LayerType() gopacket.LayerType {
	return EAPOLTypeMetadata[a].LayerType
}

type errorDecoderForEAPOLType int

func (a *errorDecoderForEAPOLType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}
func (a *errorDecoderForEAPOLType) Error() string {
	return fmt.Sprintf("Unable to decode EAPOLType %d", int(*a))
}

var errorDecodersForEAPOLType [256]errorDecoderForEAPOLType
var EAPOLTypeMetadata [256]EnumMetadata

func initUnknownTypesForEAPOLType() {
	for i := 0; i < 256; i++ {
		errorDecodersForEAPOLType[i] = errorDecoderForEAPOLType(i)
		EAPOLTypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForEAPOLType[i],
			Name:       "UnknownEAPOLType",
		}
	}
}

func (a ProtocolFamily) Decode(data []byte, p gopacket.PacketBuilder) error {
	return ProtocolFamilyMetadata[a].DecodeWith.Decode(data, p)
}
func (a ProtocolFamily) String() string {
	return ProtocolFamilyMetadata[a].Name
}
func (a ProtocolFamily) LayerType() gopacket.LayerType {
	return ProtocolFamilyMetadata[a].LayerType
}

type errorDecoderForProtocolFamily int

func (a *errorDecoderForProtocolFamily) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}
func (a *errorDecoderForProtocolFamily) Error() string {
	return fmt.Sprintf("Unable to decode ProtocolFamily %d", int(*a))
}

var errorDecodersForProtocolFamily [256]errorDecoderForProtocolFamily
var ProtocolFamilyMetadata [256]EnumMetadata

func initUnknownTypesForProtocolFamily() {
	for i := 0; i < 256; i++ {
		errorDecodersForProtocolFamily[i] = errorDecoderForProtocolFamily(i)
		ProtocolFamilyMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForProtocolFamily[i],
			Name:       "UnknownProtocolFamily",
		}
	}
}

func (a Dot11Type) Decode(data []byte, p gopacket.PacketBuilder) error {
	return Dot11TypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a Dot11Type) String() string {
	return Dot11TypeMetadata[a].Name
}
func (a Dot11Type) LayerType() gopacket.LayerType {
	return Dot11TypeMetadata[a].LayerType
}

type errorDecoderForDot11Type int

func (a *errorDecoderForDot11Type) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}
func (a *errorDecoderForDot11Type) Error() string {
	return fmt.Sprintf("Unable to decode Dot11Type %d", int(*a))
}

var errorDecodersForDot11Type [256]errorDecoderForDot11Type
var Dot11TypeMetadata [256]EnumMetadata

func initUnknownTypesForDot11Type() {
	for i := 0; i < 256; i++ {
		errorDecodersForDot11Type[i] = errorDecoderForDot11Type(i)
		Dot11TypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForDot11Type[i],
			Name:       "UnknownDot11Type",
		}
	}
}

func (a USBTransportType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return USBTransportTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a USBTransportType) String() string {
	return USBTransportTypeMetadata[a].Name
}
func (a USBTransportType) LayerType() gopacket.LayerType {
	return USBTransportTypeMetadata[a].LayerType
}

type errorDecoderForUSBTransportType int

func (a *errorDecoderForUSBTransportType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}
func (a *errorDecoderForUSBTransportType) Error() string {
	return fmt.Sprintf("Unable to decode USBTransportType %d", int(*a))
}

var errorDecodersForUSBTransportType [256]errorDecoderForUSBTransportType
var USBTransportTypeMetadata [256]EnumMetadata

func initUnknownTypesForUSBTransportType() {
	for i := 0; i < 256; i++ {
		errorDecodersForUSBTransportType[i] = errorDecoderForUSBTransportType(i)
		USBTransportTypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForUSBTransportType[i],
			Name:       "UnknownUSBTransportType",
		}
	}
}
