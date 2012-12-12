// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
)

// TCP is the layer for TCP headers.
type TCP struct {
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
}

// LayerType returns LayerTypeTCP
func (t *TCP) LayerType() LayerType { return LayerTypeTCP }

func decodeTCP(data []byte) (out DecodeResult, err error) {
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
	out.RemainingBytes = data[tcp.DataOffset*4:]
	out.DecodedLayer = tcp
	out.NextDecoder = decodePayload
	out.TransportLayer = tcp
	return
}

func (t *TCP) TransportFlow() Flow {
	return Flow{LayerTypeTCP, string(t.sPort), string(t.dPort)}
}
