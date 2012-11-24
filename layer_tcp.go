// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

type TCP struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8
	Flags      TcpFlag
	Window     uint16
	Checksum   uint16
	Urgent     uint16
}

func (t *TCP) LayerType() LayerType { return TYPE_TCP }

type TcpFlag uint16

const (
	TCP_FIN TcpFlag = 1 << iota
	TCP_SYN
	TCP_RST
	TCP_PSH
	TCP_ACK
	TCP_URG
	TCP_ECE
	TCP_CWR
	TCP_NS
)

var decodeTcp decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	tcp := &TCP{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		Seq:        binary.BigEndian.Uint32(data[4:8]),
		Ack:        binary.BigEndian.Uint32(data[8:12]),
		DataOffset: (data[12] & 0xF0) >> 4,
		Flags:      TcpFlag(binary.BigEndian.Uint16(data[12:14]) & 0x1FF),
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Urgent:     binary.BigEndian.Uint16(data[18:20]),
	}
	out.left = data[tcp.DataOffset*4:]
	out.layer = tcp
	out.next = decodePayload
	s.transport = tcp
	return
}

func (f TcpFlag) String() string {
	var sflags []string
	if 0 != (f & TCP_SYN) {
		sflags = append(sflags, "syn")
	}
	if 0 != (f & TCP_FIN) {
		sflags = append(sflags, "fin")
	}
	if 0 != (f & TCP_ACK) {
		sflags = append(sflags, "ack")
	}
	if 0 != (f & TCP_PSH) {
		sflags = append(sflags, "psh")
	}
	if 0 != (f & TCP_RST) {
		sflags = append(sflags, "rst")
	}
	if 0 != (f & TCP_URG) {
		sflags = append(sflags, "urg")
	}
	if 0 != (f & TCP_NS) {
		sflags = append(sflags, "ns")
	}
	if 0 != (f & TCP_CWR) {
		sflags = append(sflags, "cwr")
	}
	if 0 != (f & TCP_ECE) {
		sflags = append(sflags, "ece")
	}
	return fmt.Sprintf("[%s]", strings.Join(sflags, " "))
}

