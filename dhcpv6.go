// Copyright 2018 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
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
	DHCPv6MsgTypeAdverstise
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
	case DHCPv6MsgTypeAdverstise:
		return "Adverstise"
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
	MsgType       uint8
	TransactionId []byte
	HopCount      uint8
	LinkAddr      net.IP
	PeerAddr      net.IP
	Options       DHCPv6Options
}

// LayerType returns gopacket.LayerTypeDHCPv6
func (d *DHCPv6) LayerType() gopacket.LayerType { return LayerTypeDHCPv6 }

// DecodeFromBytes decodes the given bytes into this layer.
func (d *DHCPv6) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	d.Options = d.Options[:0]
	d.MsgType = DHCPv6MsgType(data[0])

	offset := 0
	if d.MsgType == DHCPv6MsgTypeRelayForward || d.MsgType == DHCPv6MsgTypeRelayForward {
		d.HopCount = data[1]
		d.LinkAddr = net.IP(data[2:18])
		d.PeerAddr = net.IP(data[18:34])
		offset = 34
	} else {
		d.TransactionId = data[1:4]
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
		copy(data[2:18], d.LinkAddr.To6())
		copy(data[18:34], d.PeerAddr.To6())
		offset = 34
	} else {
		copy(data[1:4], d.TransactionId)
		offset = 4
	}

	if len(d.Options) > 0 {
		for _, o := range d.Options {
			if err := o.encode(data[offset:]); err != nil {
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
type DHCPv6StatusCode byte

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

// DHCPv6Duid represents a DHCP DUID - RFC-3315
type DHCPv6Duid byte

// Constants for the DHCPv6Duid.
const (
	DHCPv6DuidLLT DHCPv6Duid = iota + 1
	DHCPv6DuidEN
	DHCPv6DuidLL
)

// String returns a string version of a DHCPv6Duid.
func (o DHCPv6Duid) String() string {
	switch o {
	case DHCPv6DuidLLT:
		return "LLT"
	case DHCPv6DuidEN:
		return "EN"
	case DHCPv6DuidLL:
		return "LL"
	default:
		return "Unknown"
	}
}

// DHCPv6Opt represents a DHCP option or parameter from RFC-3315
type DHCPv6Opt uint16

// Constants for the DHCPv6Opt options.
const (
	DHCPv6OptClientID           DHCPv6Opt = 1
	DHCPv6OptServerID           DHCPv6Opt = 2
	DHCPv6OptIANA               DHCPv6Opt = 3
	DHCPv6OptIATA               DHCPv6Opt = 4
	DHCPv6OptIAAddr             DHCPv6Opt = 5
	DHCPv6OptOro                DHCPv6Opt = 6
	DHCPv6OptPreference         DHCPv6Opt = 7
	DHCPv6OptElapsedTime        DHCPv6Opt = 8
	DHCPv6OptRelayMessage       DHCPv6Opt = 9
	DHCPv6OptAuth               DHCPv6Opt = 11
	DHCPv6OptUnicast            DHCPv6Opt = 12
	DHCPv6OptStatusCode         DHCPv6Opt = 13
	DHCPv6OptRapidCommit        DHCPv6Opt = 14
	DHCPv6OptUserClass          DHCPv6Opt = 15
	DHCPv6OptVendorClass        DHCPv6Opt = 16
	DHCPv6OptVendorOpts         DHCPv6Opt = 17
	DHCPv6OptInterfaceID        DHCPv6Opt = 18
	DHCPv6OptReconfigureMessage DHCPv6Opt = 19
	DHCPv6OptReconfigureAccept  DHCPv6Opt = 20
)

// String returns a string version of a DHCPv6Opt.
func (o DHCPv6Opt) String() string {
	switch o {
	case DHCPv6OptClientID:
		return "ClientID"
	case DHCPv6OptServerID:
		return "ServerID"
	case DHCPv6OptIANA:
		return "IA_NA"
	case DHCPv6OptIATA:
		return "IA_TA"
	case DHCPv6OptIAAddr:
		return "IAAddr"
	case DHCPv6OptOro:
		return "Oro"
	case DHCPv6OptPreference:
		return "Preference"
	case DHCPv6OptElapsedTime:
		return "ElapsedTime"
	case DHCPv6OptRelayMessage:
		return "RelayMessage"
	case DHCPv6OptAuth:
		return "Auth"
	case DHCPv6OptUnicast:
		return "Unicast"
	case DHCPv6OptStatusCode:
		return "StatusCode"
	case DHCPv6OptRapidCommit:
		return "RapidCommit"
	case DHCPv6OptUserClass:
		return "UserClass"
	case DHCPv6OptVendorClass:
		return "VendorClass"
	case DHCPv6OptVendorOpts:
		return "VendorOpts"
	case DHCPv6OptInterfaceID:
		return "InterfaceID"
	case DHCPv6OptReconfigureMessage:
		return "ReconfigureMessage"
	case DHCPv6OptReconfigureAccept:
		return "ReconfigureAccept"
	default:
		return "Unknown"
	}
}

// DHCPv6Options is used to get nicely printed option lists which would normally
// be cut off after 5 options.
type DHCPv6Options []DHCPv6Option

// String returns a string version of the options list.
func (o DHCPv6Options) String() string {
	buf := &bytes.Buffer{}
	buf.WriteByte('[')
	for i, opt := range o {
		buf.WriteString(opt.String())
		if i+1 != len(o) {
			buf.WriteString(", ")
		}
	}
	buf.WriteByte(']')
	return buf.String()
}

// DHCPv6Option rerpresents a DHCP option.
type DHCPv6Option struct {
	Code   DHCPv6Opt
	Length uint16
	Data   []byte
}

// String returns a string version of a DHCP Option.
func (o DHCPv6Option) String() string {
	switch o.Type {

	case DHCPv6OptHostname, DHCPv6OptMeritDumpFile, DHCPv6OptDomainName, DHCPv6OptRootPath,
		DHCPv6OptExtensionsPath, DHCPv6OptNISDomain, DHCPv6OptNetBIOSTCPScope, DHCPv6OptXFontServer,
		DHCPv6OptXDisplayManager, DHCPv6OptMessage, DHCPv6OptDomainSearch: // string
		return fmt.Sprintf("Option(%s:%s)", o.Type, string(o.Data))

	case DHCPv6OptMessageType:
		if len(o.Data) != 1 {
			return fmt.Sprintf("Option(%s:INVALID)", o.Type)
		}
		return fmt.Sprintf("Option(%s:%s)", o.Type, DHCPMsgType(o.Data[0]))

	case DHCPv6OptSubnetMask, DHCPv6OptServerID, DHCPv6OptBroadcastAddr,
		DHCPv6OptSolicitAddr, DHCPv6OptRequestIP: // net.IP
		if len(o.Data) < 4 {
			return fmt.Sprintf("Option(%s:INVALID)", o.Type)
		}
		return fmt.Sprintf("Option(%s:%s)", o.Type, net.IP(o.Data))

	case DHCPv6OptT1, DHCPv6OptT2, DHCPv6OptLeaseTime, DHCPv6OptPathMTUAgingTimeout,
		DHCPv6OptARPTimeout, DHCPv6OptTCPKeepAliveInt: // uint32
		if len(o.Data) != 4 {
			return fmt.Sprintf("Option(%s:INVALID)", o.Type)
		}
		return fmt.Sprintf("Option(%s:%d)", o.Type,
			uint32(o.Data[0])<<24|uint32(o.Data[1])<<16|uint32(o.Data[2])<<8|uint32(o.Data[3]))

	case DHCPv6OptParamsRequest:
		buf := &bytes.Buffer{}
		buf.WriteString(fmt.Sprintf("Option(%s:", o.Type))
		for i, v := range o.Data {
			buf.WriteString(DHCPv6Opt(v).String())
			if i+1 != len(o.Data) {
				buf.WriteByte(',')
			}
		}
		buf.WriteString(")")
		return buf.String()

	default:
		return fmt.Sprintf("Option(%s:%v)", o.Type, o.Data)
	}
}

// NewDHCPv6Option constructs a new DHCPv6Option with a given type and data.
func NewDHCPv6Option(code DHCPv6Opt, data []byte) DHCPv6Option {
	o := DHCPv6Option{Code: code}
	if data != nil {
		o.Data = data
		o.Length = uint16(len(data))
	}

	return o
}

func (o *DHCPv6Option) encode(b []byte) error {
	copy(b[0:2], binary.BigEndian.Uint16(o.Code))
	copy(b[2:4], binary.BigEndian.Uint16(o.Length))
	copy(b[4:], o.Data)

	return nil
}

func (o *DHCPv6Option) decode(data []byte) error {
	if len(data) < 2 {
		return errors.New("Not enough data to decode")
	}
	o.Code = DHCPv6Opt(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 3 {
		return errors.New("Not enough data to decode")
	}
	o.Length = binary.BigEndian.Uint16(data[2:4])
	o.Data = data[4 : 4+o.Length]
	return nil
}
