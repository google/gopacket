// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
	"encoding/binary"
	"errors"
	"fmt"
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

func (t TCPOption) String() string {
	switch t.OptionType {
	case 1:
		return "NOP"
	case 8:
		if len(t.OptionData) == 8 {
			return fmt.Sprintf("TSOPT:%v/%v",
				binary.BigEndian.Uint32(t.OptionData[:4]),
				binary.BigEndian.Uint32(t.OptionData[4:8]))
		}
	}
	return fmt.Sprintf("TCPOption(%v:%v)", t.OptionType, t.OptionData)
}

// LayerType returns gopacket.LayerTypeTCP
func (t *TCP) LayerType() gopacket.LayerType { return LayerTypeTCP }

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
	p.AddLayer(tcp)
	p.SetTransportLayer(tcp)
	if tcp.DataOffset < 5 {
		return fmt.Errorf("Invalid TCP data offset %d < 5", tcp.DataOffset)
	}
	dataStart := int(tcp.DataOffset) * 4
	if dataStart > len(data) {
		p.SetTruncated()
		tcp.payload = nil
		tcp.contents = data
		return errors.New("TCP data offset greater than packet length")
	}
	tcp.contents = data[:dataStart]
	tcp.payload = data[dataStart:]
	// From here on, data points just to the header options.
	data = data[20:dataStart]
	for len(data) > 0 {
		if tcp.Options == nil {
			// Pre-allocate to avoid growing the slice too much.
			tcp.Options = make([]TCPOption, 0, 4)
		}
		tcp.Options = append(tcp.Options, TCPOption{OptionType: data[0]})
		opt := &tcp.Options[len(tcp.Options)-1]
		switch opt.OptionType {
		case 0: // End of options
			opt.OptionLength = 1
			tcp.Padding = data[1:]
			break
		case 1: // 1 byte padding
			opt.OptionLength = 1
		default:
			opt.OptionLength = data[1]
			if opt.OptionLength < 2 {
				return fmt.Errorf("Invalid TCP option length %d < 2", opt.OptionLength)
			} else if int(opt.OptionLength) > len(data) {
				return fmt.Errorf("Invalid TCP option length %d exceeds remaining %d bytes", opt.OptionLength, len(data))
			}
			opt.OptionData = data[2:opt.OptionLength]
		}
		data = data[opt.OptionLength:]
	}
	return p.NextDecoder(gopacket.LayerTypePayload)
}

func (t *TCP) TransportFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointTCPPort, t.sPort, t.dPort)
}
