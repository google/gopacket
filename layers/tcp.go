// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package layers

import (
	"encoding/binary"
	"github.com/gconnell/gopacket"
)

// TCP is the layer for TCP headers.
type TCP struct {
	baseLayer
	SrcPort                                    uint16
	DstPort                                    uint16
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

// LayerType returns gopacket.LayerTypeTCP
func (t *TCP) LayerType() gopacket.LayerType { return LayerTypeTCP }

func decodeTCP(data []byte, c gopacket.LayerCollector) error {
	tcp := &TCP{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		sPort:      data[0:2],
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
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
	c.AddLayer(tcp)
	return c.NextDecoder(gopacket.LayerTypePayload)
}

func (t *TCP) TransportFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointTCPPort, t.sPort, t.dPort)
}
