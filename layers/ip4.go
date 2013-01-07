// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/gconnell/gopacket"
	"net"
)

// IPv4 is the header of an IP packet.
type IPv4 struct {
	baseLayer
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	Id         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   IPProtocol
	Checksum   uint16
	SrcIP      []byte
	DstIP      []byte
	Options    []IPv4Option
	Padding    []byte
}

// LayerType returns LayerTypeIPv4
func (i *IPv4) LayerType() gopacket.LayerType { return LayerTypeIPv4 }
func (i *IPv4) NetworkFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointIP, i.SrcIP, i.DstIP)
}

// String returns a human-readable string for this layer.
func (i *IPv4) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "IPv4: %v->%v (%v)\n", net.IP(i.SrcIP), net.IP(i.DstIP), i.Protocol)
	for _, opt := range i.Options {
		fmt.Fprintln(&b, "  option:", opt)
	}
	b.WriteString(i.baseLayer.String())
	return b.String()
}

type IPv4Option struct {
	OptionType   uint8
	OptionLength uint8
	OptionData   []byte
}

func (i *IPv4Option) String() string {
	return fmt.Sprintf("IPv4Option(%v:%v)", i.OptionType, i.OptionData)
}

func decodeIPv4(data []byte, p gopacket.PacketBuilder) error {
	flagsfrags := binary.BigEndian.Uint16(data[6:8])
	ip := &IPv4{
		Version:    uint8(data[0]) >> 4,
		IHL:        uint8(data[0]) & 0x0F,
		TOS:        data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
		Id:         binary.BigEndian.Uint16(data[4:6]),
		Flags:      uint8(flagsfrags >> 13),
		FragOffset: flagsfrags & 0x1FFF,
		TTL:        data[8],
		Protocol:   IPProtocol(data[9]),
		Checksum:   binary.BigEndian.Uint16(data[10:12]),
		SrcIP:      data[12:16],
		DstIP:      data[16:20],
	}
	pEnd := int(ip.Length)
	if pEnd > len(data) {
		pEnd = len(data)
	}
	d := data[20 : ip.IHL*4]
	// Pull out IP options
	for len(d) > 0 {
		if ip.Options == nil {
			// Pre-allocate to avoid growing the slice too much.
			ip.Options = make([]IPv4Option, 0, 4)
		}
		opt := IPv4Option{OptionType: d[0]}
		switch opt.OptionType {
		case 0: // End of options
			opt.OptionLength = 1
			ip.Options = append(ip.Options, opt)
			ip.Padding = d[1:]
			break
		case 1: // 1 byte padding
			opt.OptionLength = 1
		default:
			opt.OptionLength = d[1]
			opt.OptionData = d[2:opt.OptionLength]
		}
		ip.Options = append(ip.Options, opt)
		d = d[opt.OptionLength:]
	}
	ip.contents = data[:ip.IHL*4]
	ip.payload = data[ip.IHL*4 : pEnd]
	p.AddLayer(ip)
	p.SetNetworkLayer(ip)
	return p.NextDecoder(ip.Protocol)
}
