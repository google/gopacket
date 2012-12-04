// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
)

// ARP is a ARP packet header.
type ARP struct {
	AddrType          LinkType
	Protocol          EthernetType
	HwAddressSize     uint8
	ProtAddressSize   uint8
	Operation         uint16
	SourceHwAddress   []byte
	SourceProtAddress []byte
	DstHwAddress      []byte
	DstProtAddress    []byte
}

func (arp *ARP) String() (s string) {
	switch arp.Operation {
	case 1:
		s = "ARP request"
	case 2:
		s = "ARP Reply"
	}
	return
}

// LayerType returns LayerTypeARP
func (arp *ARP) LayerType() LayerType { return LayerTypeARP }

func decodeARP(data []byte) (out DecodeResult, err error) {
	arp := &ARP{
		AddrType:        LinkType(binary.BigEndian.Uint16(data[0:2])),
		Protocol:        EthernetType(binary.BigEndian.Uint16(data[2:4])),
		HwAddressSize:   data[4],
		ProtAddressSize: data[5],
		Operation:       binary.BigEndian.Uint16(data[6:8]),
	}
	arp.SourceHwAddress = data[8 : 8+arp.HwAddressSize]
	arp.SourceProtAddress = data[8+arp.HwAddressSize : 8+arp.HwAddressSize+arp.ProtAddressSize]
	arp.DstHwAddress = data[8+arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+arp.ProtAddressSize]
	arp.DstProtAddress = data[8+2*arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+2*arp.ProtAddressSize]

	out.DecodedLayer = arp
	out.RemainingBytes = data[8+2*arp.HwAddressSize+2*arp.ProtAddressSize:]
	out.NextDecoder = decodePayload
	return
}
