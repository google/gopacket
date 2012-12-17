// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"fmt"
	"github.com/gconnell/gopacket"
)

// CDPType is the type of each TLV value in a CDP packet.
type CDPType uint16

// CDP is a packet layer containing the Cisco Discovery Protocol.
// See http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm#31885
type CDP struct {
	Version  byte
	TTL      byte
	Checksum uint16
	Values   []CDPValue
}

// LayerType returns gopacket.LayerTypeCDP.
func (c *CDP) LayerType() gopacket.LayerType { return LayerTypeCDP }

// CDPValue is a TLV value inside a CDP packet layer.
type CDPValue struct {
	Type   CDPType
	Length uint16
	Value  []byte
}

func decodeCDP(data []byte) (out gopacket.DecodeResult, err error) {
	c := &CDP{
		Version:  data[0],
		TTL:      data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
	}
	if c.Version != 1 {
		err = fmt.Errorf("Invalid CDP version number %d", c.Version)
		return
	}
	data = data[4:]
	for len(data) > 0 {
		val := CDPValue{
			Type:   CDPType(binary.BigEndian.Uint16(data[:2])),
			Length: binary.BigEndian.Uint16(data[2:4]),
		}
		if val.Length < 4 {
			err = fmt.Errorf("Invalid CDP value length %d", val.Length)
			return
		}
		val.Value = data[4:val.Length]
		c.Values = append(c.Values, val)
		data = data[val.Length:]
	}
	out.DecodedLayer = c
	return
}
