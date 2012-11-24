// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

type UDP struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

func (u *UDP) LayerType() LayerType { return TYPE_UDP }

var decodeUdp decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	out.layer = &UDP{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}
	out.next = decodePayload
	out.left = data[8:]
	return
}

