// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

// IPv4 is the header of an IP packet.
type IPv4 struct {
	Version    uint8
	Ihl        uint8
	Tos        uint8
	Length     uint16
	Id         uint16
	Flags      uint8
	FragOffset uint16
	Ttl        uint8
	Protocol   IpProtocol
	Checksum   uint16
	SrcIp      IPAddress
	DstIp      IPAddress
}

func (i *IPv4) LayerType() LayerType { return TYPE_IP4 }
func (i *IPv4) SrcNetAddr() Address  { return i.SrcIp }
func (i *IPv4) DstNetAddr() Address  { return i.DstIp }

var decodeIp4 decoderFunc = func(data []byte, s *specificLayers) (out decodeResult) {
	flagsfrags := binary.BigEndian.Uint16(data[6:8])
	ip := &IPv4{
		Version:    uint8(data[0]) >> 4,
		Ihl:        uint8(data[0]) & 0x0F,
		Tos:        data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
		Id:         binary.BigEndian.Uint16(data[4:6]),
		Flags:      uint8(flagsfrags >> 13),
		FragOffset: flagsfrags & 0x1FFF,
		Ttl:        data[8],
		Protocol:   IpProtocol(data[9]),
		Checksum:   binary.BigEndian.Uint16(data[10:12]),
		SrcIp:      data[12:16],
		DstIp:      data[16:20],
	}
	pEnd := int(ip.Length)
	if pEnd > len(data) {
		pEnd = len(data)
	}
	out.left = data[ip.Ihl*4 : pEnd]
	out.layer = ip
	out.next = ip.Protocol
	s.network = ip
	return
}


