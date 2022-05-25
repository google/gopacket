// Copyright 2018 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
)

// DHCPv6MsgType represents a DHCPv6 operation
type DHCPv6MsgType byte

// Constants that represent DHCP operations
const (
	DHCPv6MsgTypeUnspecified DHCPv6MsgType = iota
	DHCPv6MsgTypeSolicit
	DHCPv6MsgTypeAdvertise
	DHCPv6MsgTypeRequest
	DHCPv6MsgTypeConfirm
	DHCPv6MsgTypeRenew
	DHCPv6MsgTypeRebind
	DHCPv6MsgTypeReply
	DHCPv6MsgTypeRelease
	DHCPv6MsgTypeDecline
	DHCPv6MsgTypeReconfigure
	DHCPv6MsgTypeInformationRequest
	DHCPv6MsgTypeRelayForward
	DHCPv6MsgTypeRelayReply
)

// String returns a string version of a DHCPv6MsgType.
func (o DHCPv6MsgType) String() string {
	switch o {
	case DHCPv6MsgTypeUnspecified:
		return "Unspecified"
	case DHCPv6MsgTypeSolicit:
		return "Solicit"
	case DHCPv6MsgTypeAdvertise:
		return "Advertise"
	case DHCPv6MsgTypeRequest:
		return "Request"
	case DHCPv6MsgTypeConfirm:
		return "Confirm"
	case DHCPv6MsgTypeRenew:
		return "Renew"
	case DHCPv6MsgTypeRebind:
		return "Rebind"
	case DHCPv6MsgTypeReply:
		return "Reply"
	case DHCPv6MsgTypeRelease:
		return "Release"
	case DHCPv6MsgTypeDecline:
		return "Decline"
	case DHCPv6MsgTypeReconfigure:
		return "Reconfigure"
	case DHCPv6MsgTypeInformationRequest:
		return "InformationRequest"
	case DHCPv6MsgTypeRelayForward:
		return "RelayForward"
	case DHCPv6MsgTypeRelayReply:
		return "RelayReply"
	default:
		return "Unknown"
	}
}

// DHCPv6 contains data for a single DHCP packet.
type DHCPv6 struct {
	BaseLayer
	MsgType       DHCPv6MsgType
	HopCount      uint8
	LinkAddr      net.IP
	PeerAddr      net.IP
	TransactionID []byte
	Options       DHCPv6Options
}

// LayerType returns gopacket.LayerTypeDHCPv6
func (d *DHCPv6) LayerType() gopacket.LayerType { return LayerTypeDHCPv6 }

// DecodeFromBytes decodes the given bytes into this layer.
func (d *DHCPv6) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		df.SetTruncated()
		return fmt.Errorf("DHCPv6 length %d too short", len(data))
	}
	d.BaseLayer = BaseLayer{Contents: data}
	d.Options = d.Options[:0]
	d.MsgType = DHCPv6MsgType(data[0])

	offset := 0
	if d.MsgType == DHCPv6MsgTypeRelayForward || d.MsgType == DHCPv6MsgTypeRelayReply {
		if len(data) < 34 {
			df.SetTruncated()
			return fmt.Errorf("DHCPv6 length %d too short for message type %d", len(data), d.MsgType)
		}
		d.HopCount = data[1]
		d.LinkAddr = net.IP(data[2:18])
		d.PeerAddr = net.IP(data[18:34])
		offset = 34
	} else {
		d.TransactionID = data[1:4]
		offset = 4
	}

	stop := len(data)
	for offset < stop {
		o := DHCPv6Option{}
		if err := o.decode(data[offset:]); err != nil {
			return err
		}
		d.Options = append(d.Options, o)
		offset += int(o.Length) + 4 // 2 from option code, 2 from option length
	}

	return nil
}

// Len returns the length of a DHCPv6 packet.
func (d *DHCPv6) Len() int {
	n := 1
	if d.MsgType == DHCPv6MsgTypeRelayForward || d.MsgType == DHCPv6MsgTypeRelayReply {
		n += 33
	} else {
		n += 3
	}

	for _, o := range d.Options {
		n += int(o.Length) + 4 // 2 from option code, 2 from option length
	}

	return n
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (d *DHCPv6) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	plen := int(d.Len())

	data, err := b.PrependBytes(plen)
	if err != nil {
		return err
	}

	offset := 0
	data[0] = byte(d.MsgType)
	if d.MsgType == DHCPv6MsgTypeRelayForward || d.MsgType == DHCPv6MsgTypeRelayReply {
		data[1] = byte(d.HopCount)
		copy(data[2:18], d.LinkAddr.To16())
		copy(data[18:34], d.PeerAddr.To16())
		offset = 34
	} else {
		copy(data[1:4], d.TransactionID)
		offset = 4
	}

	if len(d.Options) > 0 {
		for _, o := range d.Options {
			if err := o.encode(data[offset:], opts); err != nil {
				return err
			}
			offset += int(o.Length) + 4 // 2 from option code, 2 from option length
		}
	}
	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (d *DHCPv6) CanDecode() gopacket.LayerClass {
	return LayerTypeDHCPv6
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (d *DHCPv6) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeDHCPv6(data []byte, p gopacket.PacketBuilder) error {
	dhcp := &DHCPv6{}
	err := dhcp.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(dhcp)
	return p.NextDecoder(gopacket.LayerTypePayload)
}

// DHCPv6StatusCode represents a DHCP status code - RFC-3315
type DHCPv6StatusCode uint16

// Constants for the DHCPv6StatusCode.
const (
	DHCPv6StatusCodeSuccess DHCPv6StatusCode = iota
	DHCPv6StatusCodeUnspecFail
	DHCPv6StatusCodeNoAddrsAvail
	DHCPv6StatusCodeNoBinding
	DHCPv6StatusCodeNotOnLink
	DHCPv6StatusCodeUseMulticast
)

// String returns a string version of a DHCPv6StatusCode.
func (o DHCPv6StatusCode) String() string {
	switch o {
	case DHCPv6StatusCodeSuccess:
		return "Success"
	case DHCPv6StatusCodeUnspecFail:
		return "UnspecifiedFailure"
	case DHCPv6StatusCodeNoAddrsAvail:
		return "NoAddressAvailable"
	case DHCPv6StatusCodeNoBinding:
		return "NoBinding"
	case DHCPv6StatusCodeNotOnLink:
		return "NotOnLink"
	case DHCPv6StatusCodeUseMulticast:
		return "UseMulticast"
	default:
		return "Unknown"
	}
}

// DHCPv6DUIDType represents a DHCP DUID - RFC-3315
type DHCPv6DUIDType uint16

// Constants for the DHCPv6DUIDType.
const (
	DHCPv6DUIDTypeLLT DHCPv6DUIDType = iota + 1
	DHCPv6DUIDTypeEN
	DHCPv6DUIDTypeLL
	DHCPv6DUIDTypeUUID
)

// String returns a string version of a DHCPv6DUIDType.
func (o DHCPv6DUIDType) String() string {
	switch o {
	case DHCPv6DUIDTypeLLT:
		return "LLT"
	case DHCPv6DUIDTypeEN:
		return "EN"
	case DHCPv6DUIDTypeLL:
		return "LL"
	case DHCPv6DUIDTypeUUID:
		return "UUID"
	default:
		return "Unknown"
	}
}

// DHCPv6DUID means DHCP Unique Identifier as stated in RFC 3315, section 9 (https://tools.ietf.org/html/rfc3315#page-19)
type DHCPv6DUID struct {
	Type DHCPv6DUIDType
	// LLT, LL
	HardwareType []byte
	// EN
	EnterpriseNumber []byte
	// LLT
	Time []byte
	// LLT, LL
	LinkLayerAddress net.HardwareAddr
	// EN
	Identifier []byte
	// UUID
	UniqueIdentifier []byte
}

// DecodeFromBytes decodes the given bytes into a DHCPv6DUID
func (d *DHCPv6DUID) DecodeFromBytes(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("Not enough bytes to decode: %d", len(data))
	}

	d.Type = DHCPv6DUIDType(binary.BigEndian.Uint16(data[:2]))
	if d.Type == DHCPv6DUIDTypeLLT || d.Type == DHCPv6DUIDTypeLL {
		if len(data) < 4 {
			return fmt.Errorf("Not enough bytes to decode: %d", len(data))
		}
		d.HardwareType = data[2:4]
	}

	if d.Type == DHCPv6DUIDTypeLLT {
		if len(data) < 8 {
			return fmt.Errorf("Not enough bytes to decode: %d", len(data))
		}
		d.Time = data[4:8]
		d.LinkLayerAddress = net.HardwareAddr(data[8:])
	} else if d.Type == DHCPv6DUIDTypeEN {
		if len(data) < 6 {
			return fmt.Errorf("Not enough bytes to decode: %d", len(data))
		}
		d.EnterpriseNumber = data[2:6]
		d.Identifier = data[6:]
	} else if d.Type == DHCPv6DUIDTypeUUID {
		d.UniqueIdentifier = data[2:]
	} else { // DHCPv6DUIDTypeLL
		if len(data) < 4 {
			return fmt.Errorf("Not enough bytes to decode: %d", len(data))
		}
		d.LinkLayerAddress = net.HardwareAddr(data[4:])
	}

	return nil
}

// Encode encodes the DHCPv6DUID in a slice of bytes
func (d *DHCPv6DUID) Encode() []byte {
	length := d.Len()
	data := make([]byte, length)
	binary.BigEndian.PutUint16(data[0:2], uint16(d.Type))

	if d.Type == DHCPv6DUIDTypeLLT || d.Type == DHCPv6DUIDTypeLL {
		copy(data[2:4], d.HardwareType)
	}

	if d.Type == DHCPv6DUIDTypeLLT {
		copy(data[4:8], d.Time)
		copy(data[8:], d.LinkLayerAddress)
	} else if d.Type == DHCPv6DUIDTypeEN {
		copy(data[2:6], d.EnterpriseNumber)
		copy(data[6:], d.Identifier)
	} else {
		copy(data[4:], d.LinkLayerAddress)
	}

	return data
}

// Len returns the length of the DHCPv6DUID, respecting the type
func (d *DHCPv6DUID) Len() int {
	length := 2 // d.Type
	if d.Type == DHCPv6DUIDTypeLLT {
		length += 2 /*HardwareType*/ + 4 /*d.Time*/ + len(d.LinkLayerAddress)
	} else if d.Type == DHCPv6DUIDTypeEN {
		length += 4 /*d.EnterpriseNumber*/ + len(d.Identifier)
	} else { // LL
		length += 2 /*d.HardwareType*/ + len(d.LinkLayerAddress)
	}

	return length
}

func (d *DHCPv6DUID) String() string {
	duid := "Type: " + d.Type.String() + ", "
	if d.Type == DHCPv6DUIDTypeLLT {
		duid += fmt.Sprintf("HardwareType: %v, Time: %v, LinkLayerAddress: %v", d.HardwareType, d.Time, d.LinkLayerAddress)
	} else if d.Type == DHCPv6DUIDTypeEN {
		duid += fmt.Sprintf("EnterpriseNumber: %v, Identifier: %v", d.EnterpriseNumber, d.Identifier)
	} else { // DHCPv6DUIDTypeLL
		duid += fmt.Sprintf("HardwareType: %v, LinkLayerAddress: %v", d.HardwareType, d.LinkLayerAddress)
	}
	return duid
}

func decodeDHCPv6DUID(data []byte) (*DHCPv6DUID, error) {
	duid := &DHCPv6DUID{}
	err := duid.DecodeFromBytes(data)
	if err != nil {
		return nil, err
	}
	return duid, nil
}

type DHCPv6IAPD struct {
	IAID [4]byte
	T1   uint32
	T2   uint32
	PD   DHCPv6PD
}

type DHCPv6PD struct {
	PrefLifeTime  uint32
	ValidLifeTime uint32
	PrefixLength  byte
	Prefix        net.IP
}

// DecodeFromBytes decodes the given bytes into a DHCPv6DUID
func (d *DHCPv6IAPD) DecodeFromBytes(data []byte) error {
	if len(data) != 41 {
		return errors.New("Not enough bytes to decode: " + string(len(data)))
	}

	copy(d.IAID[:], data[:4])
	d.T1 = binary.BigEndian.Uint32(data[4:8])
	d.T2 = binary.BigEndian.Uint32(data[8:12])

	PDType := binary.BigEndian.Uint16(data[12:14])
	if PDType != uint16(DHCPv6OptIAPrefix) {
		return errors.New("Invalid IE Included: " + string(PDType))
	}
	PDLen := binary.BigEndian.Uint16(data[14:16])
	if PDLen != 25 {
		return errors.New("Invalid Length for PD: " + string(PDLen))
	}
	if err := (&d.PD).DecodeFromBytes(data[16:]); err != nil {
		return err
	}
	return nil
}

func (pd *DHCPv6PD) DecodeFromBytes(data []byte) error {
	pd.PrefLifeTime = binary.BigEndian.Uint32(data[0:4])
	pd.ValidLifeTime = binary.BigEndian.Uint32(data[4:8])
	pd.PrefixLength = data[8]
	pd.Prefix = data[9:]
	return nil
}

func (d *DHCPv6IAPD) Encode() []byte {
	length := 41
	data := make([]byte, length)
	copy(data[0:4], d.IAID[:])
	binary.BigEndian.PutUint32(data[4:8], d.T1)
	binary.BigEndian.PutUint32(data[8:12], d.T2)
	binary.BigEndian.PutUint16(data[12:14], uint16(DHCPv6OptIAPrefix))
	binary.BigEndian.PutUint16(data[14:16], 25)
	x := (&d.PD).Encode()
	copy(data[16:41], x)
	return data
}

func (pd *DHCPv6PD) Encode() []byte {
	data := make([]byte, 25)
	binary.BigEndian.PutUint32(data[0:4], pd.PrefLifeTime)
	binary.BigEndian.PutUint32(data[4:8], pd.ValidLifeTime)
	data[8] = pd.PrefixLength
	copy(data[9:25], pd.Prefix)
	return data
}

// Implementation of Remote ID of DHCPv6 used by LDRA
// Defined in RFC 6221
type DHCPv6RemoteId struct {
	EnterpriseID [4]byte
	RemoteId     []byte
}

func (d *DHCPv6RemoteId) Encode() []byte {
	length := 4 + len(d.RemoteId)
	data := make([]byte, length)
	copy(data[0:4], d.EnterpriseID[:])
	copy(data[4:], d.RemoteId)
	return data
}

func (d *DHCPv6RemoteId) DecodeFromBytes(data []byte) error {
	copy(d.EnterpriseID[:], data[0:4])
	copy(d.RemoteId, data[4:])
	return nil
}

// Implementation of Interface Id of DHCPv6 used by LDRA
// Defined in RFC 6221
type DHCPv6IntfId struct {
	Data []byte
}

func (d *DHCPv6IntfId) Encode() []byte {
	length := len(d.Data)
	data := make([]byte, length)
	copy(data[0:length], d.Data)
	return data
}

func (d *DHCPv6IntfId) DecodeFromBytes(data []byte) error {
	copy(d.Data, data)
	return nil
}

type DHCPv6IANA struct {
	IAID [4]byte
	T1   uint32
	T2   uint32
	IA   DHCPv6IA
}

type DHCPv6IA struct {
	PrefLifeTime  uint32
	ValidLifeTime uint32
	IPv6Addr      net.IP
}

// DecodeFromBytes decodes the given bytes into a DHCPv6DUID
func (d *DHCPv6IANA) DecodeFromBytes(data []byte) error {
	if len(data) != 40 {
		return errors.New("Not enough bytes to decode: " + string(len(data)))
	}

	copy(d.IAID[:], data[:4])
	d.T1 = binary.BigEndian.Uint32(data[4:8])
	d.T2 = binary.BigEndian.Uint32(data[8:12])

	IAType := binary.BigEndian.Uint16(data[12:14])
	if IAType != uint16(DHCPv6OptIAAddr) {
		return errors.New("Invalid IE Included: " + string(IAType))
	}
	IALen := binary.BigEndian.Uint16(data[14:16])
	if IALen != 24 {
		return errors.New("Invalid Length for PD: " + string(IALen))
	}
	if err := (&d.IA).DecodeFromBytes(data[16:]); err != nil {
		return err
	}
	return nil
}

func (ia *DHCPv6IA) DecodeFromBytes(data []byte) error {
	ia.IPv6Addr = data[0:16]
	ia.PrefLifeTime = binary.BigEndian.Uint32(data[16:20])
	ia.ValidLifeTime = binary.BigEndian.Uint32(data[20:])

	return nil
}

func (d *DHCPv6IANA) Encode() []byte {
	length := 40
	data := make([]byte, length)
	copy(data[0:4], d.IAID[:])
	binary.BigEndian.PutUint32(data[4:8], d.T1)
	binary.BigEndian.PutUint32(data[8:12], d.T2)
	binary.BigEndian.PutUint16(data[12:14], uint16(DHCPv6OptIAPrefix))
	binary.BigEndian.PutUint16(data[14:16], 24)
	x := (&d.IA).Encode()
	copy(data[16:40], x)
	return data
}

func (ia *DHCPv6IA) Encode() []byte {
	data := make([]byte, 24)
	copy(data[0:16], ia.IPv6Addr)
	binary.BigEndian.PutUint32(data[16:20], ia.PrefLifeTime)
	binary.BigEndian.PutUint32(data[20:24], ia.ValidLifeTime)
	return data
}
