// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// TCP is the layer for TCP headers.
type TCP struct {
	SrcPort      uint16
	DstPort      uint16
	Seq          uint32
	Ack          uint32
	DataOffset   uint8
	Flags        TCPFlag
	Window       uint16
	Checksum     uint16
	Urgent       uint16
	sPort, dPort []byte
}

// LayerType returns LayerTypeTCP
func (t *TCP) LayerType() LayerType { return LayerTypeTCP }

type TCPFlag uint16

const (
	TCPFlagFIN TCPFlag = 1 << iota
	TCPFlagSYN
	TCPFlagRST
	TCPFlagPSH
	TCPFlagACK
	TCPFlagURG
	TCPFlagECE
	TCPFlagCWR
	TCPFlagNS
)

func decodeTCP(data []byte) (out DecodeResult, err error) {
	tcp := &TCP{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		sPort:      data[0:2],
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		dPort:      data[2:4],
		Seq:        binary.BigEndian.Uint32(data[4:8]),
		Ack:        binary.BigEndian.Uint32(data[8:12]),
		DataOffset: (data[12] & 0xF0) >> 4,
		Flags:      TCPFlag(binary.BigEndian.Uint16(data[12:14]) & 0x1FF),
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

func (f TCPFlag) String() string {
	var sflags []string
	if 0 != (f & TCPFlagSYN) {
		sflags = append(sflags, "syn")
	}
	if 0 != (f & TCPFlagFIN) {
		sflags = append(sflags, "fin")
	}
	if 0 != (f & TCPFlagACK) {
		sflags = append(sflags, "ack")
	}
	if 0 != (f & TCPFlagPSH) {
		sflags = append(sflags, "psh")
	}
	if 0 != (f & TCPFlagRST) {
		sflags = append(sflags, "rst")
	}
	if 0 != (f & TCPFlagURG) {
		sflags = append(sflags, "urg")
	}
	if 0 != (f & TCPFlagNS) {
		sflags = append(sflags, "ns")
	}
	if 0 != (f & TCPFlagCWR) {
		sflags = append(sflags, "cwr")
	}
	if 0 != (f & TCPFlagECE) {
		sflags = append(sflags, "ece")
	}
	return fmt.Sprintf("[%s]", strings.Join(sflags, "|"))
}

func (t *TCP) AppFlow() Flow {
	return Flow{LayerTypeTCP, string(t.sPort), string(t.dPort)}
}
