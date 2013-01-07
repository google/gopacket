// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/gconnell/gopacket"
)

// TCP is the layer for TCP headers.
type TCP struct {
	baseLayer
	SrcPort, DstPort                           TCPPort
	Seq                                        uint32
	Ack                                        uint32
	DataOffset                                 uint8
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	Window                                     uint16
	Checksum                                   uint16
	Urgent                                     uint16
	sPort, dPort                               []byte
	Options                                    []TCPOption
	Padding                                    []byte
}

type TCPOption struct {
	OptionType   uint8
	OptionLength uint8
	OptionData   []byte
}

func (t *TCPOption) String() string {
	return fmt.Sprintf("TCPOption(%v:%v)", t.OptionType, t.OptionData)
}

// LayerType returns gopacket.LayerTypeTCP
func (t *TCP) LayerType() gopacket.LayerType { return LayerTypeTCP }

// String returns the human-readable string for a TCP layer.
func (t *TCP) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "TCP ports:%v->%v seq:%v ack:%v window:%v cksum:%v urg:%v flags:%v\n",
		t.SrcPort, t.DstPort, t.Seq, t.Ack, t.Window, t.Checksum, t.Urgent, t.flagsString())
	for _, opt := range t.Options {
		fmt.Fprintln(&b, "  option:", &opt)
	}
	return b.String()
}

func (t *TCP) flagsString() string {
	var b bytes.Buffer
	if t.FIN {
		b.WriteByte('F')
	}
	if t.SYN {
		b.WriteByte('S')
	}
	if t.RST {
		b.WriteByte('R')
	}
	if t.PSH {
		b.WriteByte('P')
	}
	if t.ACK {
		b.WriteByte('A')
	}
	if t.URG {
		b.WriteByte('U')
	}
	if t.ECE {
		b.WriteByte('E')
	}
	if t.CWR {
		b.WriteByte('C')
	}
	if t.NS {
		b.WriteByte('N')
	}
	return b.String()
}

func decodeTCP(data []byte, p gopacket.PacketBuilder) error {
	tcp := &TCP{
		SrcPort:    TCPPort(binary.BigEndian.Uint16(data[0:2])),
		sPort:      data[0:2],
		DstPort:    TCPPort(binary.BigEndian.Uint16(data[2:4])),
		dPort:      data[2:4],
		Seq:        binary.BigEndian.Uint32(data[4:8]),
		Ack:        binary.BigEndian.Uint32(data[8:12]),
		DataOffset: (data[12] & 0xF0) >> 4,
		FIN:        data[13]&0x01 != 0,
		SYN:        data[13]&0x02 != 0,
		RST:        data[13]&0x04 != 0,
		PSH:        data[13]&0x08 != 0,
		ACK:        data[13]&0x10 != 0,
		URG:        data[13]&0x20 != 0,
		ECE:        data[13]&0x40 != 0,
		CWR:        data[13]&0x80 != 0,
		NS:         data[12]&0x01 != 0,
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Urgent:     binary.BigEndian.Uint16(data[18:20]),
	}
	hlen := tcp.DataOffset * 4
	d := data[20:hlen]
	for len(d) > 0 {
		if tcp.Options == nil {
			// Pre-allocate to avoid growing the slice too much.
			tcp.Options = make([]TCPOption, 0, 4)
		}
		opt := TCPOption{OptionType: d[0]}
		switch opt.OptionType {
		case 0: // End of options
			opt.OptionLength = 1
			tcp.Options = append(tcp.Options, opt)
			tcp.Padding = d[1:]
			break
		case 1: // 1 byte padding
			opt.OptionLength = 1
		default:
			opt.OptionLength = d[1]
			opt.OptionData = d[2:opt.OptionLength]
		}
		tcp.Options = append(tcp.Options, opt)
		d = d[opt.OptionLength:]
	}
	tcp.contents = data[:hlen]
	tcp.payload = data[hlen:]
	p.AddLayer(tcp)
	p.SetTransportLayer(tcp)
	return p.NextDecoder(gopacket.LayerTypePayload)
}

func (t *TCP) TransportFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointTCPPort, t.sPort, t.dPort)
}
