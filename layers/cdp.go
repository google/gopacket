// Copyright 2012 Google, Inc. All rights reserved.

package layers

import (
	"encoding/binary"
	"fmt"
	"github.com/gconnell/gopacket"
)

// CiscoDiscoveryType is the type of each TLV value in a CiscoDiscovery packet.
type CiscoDiscoveryType uint16

// CiscoDiscovery is a packet layer containing the Cisco Discovery Protocol.
// See http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm#31885
type CiscoDiscovery struct {
	baseLayer
	Version  byte
	TTL      byte
	Checksum uint16
	Values   []CiscoDiscoveryValue
}

// LayerType returns gopacket.LayerTypeCiscoDiscovery.
func (c *CiscoDiscovery) LayerType() gopacket.LayerType {
	return LayerTypeCiscoDiscovery
}

// CiscoDiscoveryValue is a TLV value inside a CiscoDiscovery packet layer.
type CiscoDiscoveryValue struct {
	Type   CiscoDiscoveryType
	Length uint16
	Value  []byte
}

func decodeCiscoDiscovery(data []byte, p gopacket.PacketBuilder) error {
	c := &CiscoDiscovery{
		Version:  data[0],
		TTL:      data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
	}
	if c.Version != 1 {
		return fmt.Errorf("Invalid CiscoDiscovery version number %d", c.Version)
	}
	vData := data[4:]
	for len(vData) > 0 {
		val := CiscoDiscoveryValue{
			Type:   CiscoDiscoveryType(binary.BigEndian.Uint16(vData[:2])),
			Length: binary.BigEndian.Uint16(vData[2:4]),
		}
		if val.Length < 4 {
			return fmt.Errorf("Invalid CiscoDiscovery value length %d", val.Length)
		}
		val.Value = vData[4:val.Length]
		c.Values = append(c.Values, val)
		vData = vData[val.Length:]
	}
	c.contents = data
	p.AddLayer(c)
	return nil
}
