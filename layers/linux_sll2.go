// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
)

type LinuxSLL2PacketType uint16

const (
	LinuxSLL2PacketTypeHost      LinuxSLL2PacketType = 0 // To us
	LinuxSLL2PacketTypeBroadcast LinuxSLL2PacketType = 1 // To all
	LinuxSLL2PacketTypeMulticast LinuxSLL2PacketType = 2 // To group
	LinuxSLL2PacketTypeOtherhost LinuxSLL2PacketType = 3 // To someone else
	LinuxSLL2PacketTypeOutgoing  LinuxSLL2PacketType = 4 // Outgoing of any type
	// These ones are invisible by user level
	LinuxSLL2PacketTypeLoopback  LinuxSLL2PacketType = 5 // MC/BRD frame looped back
	LinuxSLL2PacketTypeFastroute LinuxSLL2PacketType = 6 // Fastrouted frame
)

func (l LinuxSLL2PacketType) String() string {
	switch l {
	case LinuxSLL2PacketTypeHost:
		return "host"
	case LinuxSLL2PacketTypeBroadcast:
		return "broadcast"
	case LinuxSLL2PacketTypeMulticast:
		return "multicast"
	case LinuxSLL2PacketTypeOtherhost:
		return "otherhost"
	case LinuxSLL2PacketTypeOutgoing:
		return "outgoing"
	case LinuxSLL2PacketTypeLoopback:
		return "loopback"
	case LinuxSLL2PacketTypeFastroute:
		return "fastroute"
	}
	return fmt.Sprintf("Unknown(%d)", int(l))
}

type LinuxSLL2 struct {
	BaseLayer
	PacketType   LinuxSLL2PacketType
	AddrLen      uint8
	Addr         net.HardwareAddr
	ProtocolType EthernetType
	AddrType     uint16
}

// LayerType returns LayerTypeLinuxSLL2.
func (sll *LinuxSLL2) LayerType() gopacket.LayerType { return LayerTypeLinuxSLL2 }

func (sll *LinuxSLL2) CanDecode() gopacket.LayerClass {
	return LayerTypeLinuxSLL2
}

func (sll *LinuxSLL2) LinkFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointMAC, sll.Addr, nil)
}

func (sll *LinuxSLL2) NextLayerType() gopacket.LayerType {
	return sll.ProtocolType.LayerType()
}

func (sll *LinuxSLL2) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 20 {
		return errors.New("Linux SLL2 packet too small")
	}

	sll.ProtocolType = EthernetType(binary.BigEndian.Uint16(data[0:2]))
	// data[2:4] reserved
	// data[4:8] interface index
	sll.AddrType = binary.BigEndian.Uint16(data[8:10])
	sll.PacketType = LinuxSLL2PacketType(binary.BigEndian.Uint16(data[10:12]))
	sll.AddrLen = data[12]
	// > If there are more than 8 bytes, only the first 8 bytes are present, and if there are fewer
	// > than 8 bytes, there are padding bytes after the address to pad the field to 8 bytes.
	if sll.AddrLen > 8 {
		sll.AddrLen = 8
	}
	sll.Addr = net.HardwareAddr(data[13 : 13+sll.AddrLen])
	sll.BaseLayer = BaseLayer{data[:20], data[20:]}

	return nil
}

func decodeLinuxSLL2(data []byte, p gopacket.PacketBuilder) error {
	sll := &LinuxSLL2{}
	if err := sll.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(sll)
	p.SetLinkLayer(sll)
	return p.NextDecoder(sll.ProtocolType)
}
