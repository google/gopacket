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

// DHCPv4 contains data for a single DHCP packet.
type DHCPv4 struct {
	BaseLayer
	Operation    DHCPOp
	HardwareType LinkType
	HardwareLen  uint8
	HardwareOpts uint8
	Xid          uint32
	Secs         uint16
	Flags        uint16
	ClientIP     net.IP
	YourClientIP net.IP
	NextServerIP net.IP
	RelayAgentIP net.IP
	ClientHWAddr net.HardwareAddr
	ServerName   []byte
	File         []byte
	Options      DHCPv6Options
}

// LayerType returns gopacket.LayerTypeDHCPv4
func (d *DHCPv4) LayerType() gopacket.LayerType { return LayerTypeDHCPv4 }

// DecodeFromBytes decodes the given bytes into this layer.
func (d *DHCPv4) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	d.Options = d.Options[:0]
	d.Operation = DHCPOp(data[0])
	d.HardwareType = LinkType(data[1])
	d.HardwareLen = data[2]
	d.HardwareOpts = data[3]
	d.Xid = binary.BigEndian.Uint32(data[4:8])
	d.Secs = binary.BigEndian.Uint16(data[8:10])
	d.Flags = binary.BigEndian.Uint16(data[10:12])
	d.ClientIP = net.IP(data[12:16])
	d.YourClientIP = net.IP(data[16:20])
	d.NextServerIP = net.IP(data[20:24])
	d.RelayAgentIP = net.IP(data[24:28])
	d.ClientHWAddr = net.HardwareAddr(data[28 : 28+d.HardwareLen])
	d.ServerName = data[44:108]
	d.File = data[108:236]
	if binary.BigEndian.Uint32(data[236:240]) != DHCPMagic {
		return errors.New("Bad DHCP header")
	}

	if len(data) <= 240 {
		// DHCP Packet could have no option (??)
		return nil
	}

	options := data[240:]

	stop := len(options)
	start := 0
	for start < stop {
		o := DHCPv6Option{}
		if err := o.decode(options[start:]); err != nil {
			return err
		}
		if o.Type == DHCPv6OptEnd {
			break
		}
		d.Options = append(d.Options, o)
		// Check if the option is a single byte pad
		if o.Type == DHCPv6OptPad {
			start++
		} else {
			start += int(o.Length) + 2
		}
	}
	return nil
}

// Len returns the length of a DHCPv4 packet.
func (d *DHCPv4) Len() uint16 {
	n := uint16(240)
	for _, o := range d.Options {
		if o.Type == DHCPv6OptPad {
			n++
		} else {
			n += uint16(o.Length) + 2
		}
	}
	n++ // for opt end
	return n
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (d *DHCPv4) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	plen := int(d.Len())

	data, err := b.PrependBytes(plen)
	if err != nil {
		return err
	}

	data[0] = byte(d.Operation)
	data[1] = byte(d.HardwareType)
	if opts.FixLengths {
		d.HardwareLen = uint8(len(d.ClientHWAddr))
	}
	data[2] = d.HardwareLen
	data[3] = d.HardwareOpts
	binary.BigEndian.PutUint32(data[4:8], d.Xid)
	binary.BigEndian.PutUint16(data[8:10], d.Secs)
	binary.BigEndian.PutUint16(data[10:12], d.Flags)
	copy(data[12:16], d.ClientIP.To4())
	copy(data[16:20], d.YourClientIP.To4())
	copy(data[20:24], d.NextServerIP.To4())
	copy(data[24:28], d.RelayAgentIP.To4())
	copy(data[28:44], d.ClientHWAddr)
	copy(data[44:108], d.ServerName)
	copy(data[108:236], d.File)
	binary.BigEndian.PutUint32(data[236:240], DHCPMagic)

	if len(d.Options) > 0 {
		offset := 240
		for _, o := range d.Options {
			if err := o.encode(data[offset:]); err != nil {
				return err
			}
			// A pad option is only a single byte
			if o.Type == DHCPv6OptPad {
				offset++
			} else {
				offset += 2 + len(o.Data)
			}
		}
		optend := NewDHCPv6Option(DHCPv6OptEnd, nil)
		if err := optend.encode(data[offset:]); err != nil {
			return err
		}
	}
	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (d *DHCPv4) CanDecode() gopacket.LayerClass {
	return LayerTypeDHCPv4
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (d *DHCPv4) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeDHCPv4(data []byte, p gopacket.PacketBuilder) error {
	dhcp := &DHCPv4{}
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
	DHCPv6StatusCodeSuccess           DHCPv6StatusCode = iota
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
	DHCPv6DuidLLT           DHCPv6Duid = iota + 1
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
type DHCPv6Opt byte

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
	Type   DHCPv6Opt
	Length uint8
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
func NewDHCPv6Option(t DHCPv6Opt, data []byte) DHCPv6Option {
	o := DHCPv6Option{Type: t}
	if data != nil {
		o.Data = data
		o.Length = uint8(len(data))
	}
	return o
}

func (o *DHCPv6Option) encode(b []byte) error {
	switch o.Type {
	case DHCPv6OptPad, DHCPv6OptEnd:
		b[0] = byte(o.Type)
	default:
		if o.Length > 253 {
			return errors.New("data too long to encode")
		}
		b[0] = byte(o.Type)
		b[1] = o.Length
		copy(b[2:], o.Data)
	}
	return nil
}

func (o *DHCPv6Option) decode(data []byte) error {
	if len(data) < 1 {
		// Pad/End have a length of 1
		return errors.New("Not enough data to decode")
	}
	o.Type = DHCPv6Opt(data[0])
	switch o.Type {
	case DHCPv6OptPad, DHCPv6OptEnd:
		o.Data = nil
	default:
		if len(data) < 3 {
			return errors.New("Not enough data to decode")
		}
		o.Length = data[1]
		if o.Length > 253 {
			return errors.New("data too long to decode")
		}
		o.Data = data[2 : 2+o.Length]
	}
	return nil
}
