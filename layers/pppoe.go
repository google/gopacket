// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

type PPPoEOpt uint16

// Constants for PPPoE Options
const (
	PPPoEOptEndOfList        PPPoEOpt = 0x0000
	PPPoEOptServiceName      PPPoEOpt = 0x0101
	PPPoEOptAcName           PPPoEOpt = 0x0102
	PPPoEOptHostUniq         PPPoEOpt = 0x0103
	PPPoEOptAcCookie         PPPoEOpt = 0x0104
	PPPoEOptVendorSpecific   PPPoEOpt = 0x0105
	PPPoEOptRelaySessionId   PPPoEOpt = 0x0110
	PPPoEOptServiceErrorName PPPoEOpt = 0x0201
	PPPoEOptAcSystemError    PPPoEOpt = 0x0202
	PPPoEOptGenericError     PPPoEOpt = 0x0203
)

type PPPoEOption struct {
	Type   PPPoEOpt
	Length uint16
	Data   []byte
}

func (o PPPoEOption) encode(b []byte) (uint16, error) {
	binary.BigEndian.PutUint16(b[0:2], uint16(o.Type))
	binary.BigEndian.PutUint16(b[2:4], uint16(o.Length))
	copy(b[4:], o.Data)
	return (4 + o.Length), nil
}

func (o PPPoEOption) decode(b []byte) error {
	if len(b) < 4 {
		return DecOptionNotEnoughData
	}
	o.Type = PPPoEOpt(binary.BigEndian.Uint16(b[0:2]))
	o.Length = binary.BigEndian.Uint16(b[2:4])
	if int(o.Length) > len(b[4:]) {
		return DecOptionNotEnoughData
	}
	o.Data = b[4 : 4+int(o.Length)]
	return nil
}

func NewPPPoEOption(opt PPPoEOpt, data []byte) PPPoEOption {
	length := (uint16)(len(data))
	option := PPPoEOption{Type: opt, Length: length, Data: data}
	return option
}

func (o PPPoEOption) String() string {
	return fmt.Sprintf("Option(%s:%v)", o.Type, o.Data)
}

func (o PPPoEOption) length() int {
	return 4 + int(o.Length)
}

type PPPoEOptions []PPPoEOption

// String returns a string version of the options list.
func (o PPPoEOptions) String() string {
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

func (o PPPoEOptions) length() int {
	length := 0
	for _, op := range o {
		length = length + op.length()
	}
	return length
}

// String returns a string version of a PPPoEOpt.
func (o PPPoEOpt) String() string {
	switch o {
	case PPPoEOptEndOfList:
		return "EndOfList"
	case PPPoEOptServiceName:
		return "ServiceName"
	case PPPoEOptAcName:
		return "AcName"
	case PPPoEOptHostUniq:
		return "HostUniq"
	case PPPoEOptAcCookie:
		return "AcCookie"
	case PPPoEOptVendorSpecific:
		return "VendorSpecific"
	case PPPoEOptRelaySessionId:
		return "RelaySessionId"
	case PPPoEOptServiceErrorName:
		return "ServiceErrorName"
	case PPPoEOptAcSystemError:
		return "AcSystemError"
	case PPPoEOptGenericError:
		return "GenericError"
	default:
		return "Unknown"
	}
}

// PPPoE is the layer for PPPoE encapsulation headers.
type PPPoE struct {
	BaseLayer
	Version   uint8
	Type      uint8
	Code      PPPoECode
	SessionId uint16
	Length    uint16
	Options   PPPoEOptions
}

// LayerType returns gopacket.LayerTypePPPoE.
func (p *PPPoE) LayerType() gopacket.LayerType {
	return LayerTypePPPoE
}

func (p *PPPoE) DecodeOptions(data []byte, len uint16) {

	start := uint16(0)
	stop := len
	for start < stop {
		pppoeOpt := &PPPoEOption{}
		pppoeOpt.Type = PPPoEOpt(binary.BigEndian.Uint16(data[start : start+2]))
		pppoeOpt.Length = binary.BigEndian.Uint16(data[start+2 : start+4])
		if pppoeOpt.Length != 0 {
			pppoeOpt.Data = data[start+4 : start+4+pppoeOpt.Length]
		}
		start = start + 4 + pppoeOpt.Length
		p.Options = append(p.Options, *pppoeOpt)
	}

}

// decodePPPoE decodes the PPPoE header (see http://tools.ietf.org/html/rfc2516).
func decodePPPoE(data []byte, p gopacket.PacketBuilder) error {

	pppoe := &PPPoE{
		Version:   data[0] >> 4,
		Type:      data[0] & 0x0F,
		Code:      PPPoECode(data[1]),
		SessionId: binary.BigEndian.Uint16(data[2:4]),
		Length:    binary.BigEndian.Uint16(data[4:6]),
	}
	pppoe.DecodeOptions(data[6:], pppoe.Length)
	pppoe.BaseLayer = BaseLayer{data[:6], data[6 : 6+pppoe.Length]}
	p.AddLayer(pppoe)
	return p.NextDecoder(pppoe.Code)
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (p *PPPoE) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	payload := b.Bytes()

	//Pkt length with Options
	length := 6
	optLength := 0
	for _, o := range p.Options {
		optLength = optLength + o.length()
	}

	bytes, err := b.PrependBytes(length + optLength)
	if err != nil {
		return err
	}
	bytes[0] = (p.Version << 4) | p.Type
	bytes[1] = byte(p.Code)
	binary.BigEndian.PutUint16(bytes[2:], p.SessionId)
	if opts.FixLengths {
		p.Length = uint16(len(payload) + optLength)
	}
	binary.BigEndian.PutUint16(bytes[4:], p.Length)

	//Encoding the options
	start := uint16(6)
	for _, option := range p.Options {
		optLen, _ := option.encode(bytes[start:])
		start = start + optLen
	}
	return nil
}
