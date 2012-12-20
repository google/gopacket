// Copyright 2012 Google, Inc. All rights reserved.

package layers

import (
	"encoding/binary"
	"fmt"
	"github.com/gconnell/gopacket"
)

// CiscoDiscoveryProtocolType is the type of each TLV value in a CiscoDiscoveryProtocol packet.
type CiscoDiscoveryProtocolType uint16

// CiscoDiscoveryProtocol is a packet layer containing the Cisco Discovery Protocol.
// See http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm#31885
type CiscoDiscoveryProtocol struct {
	baseLayer
	Version  byte
	TTL      byte
	Checksum uint16
	Values   []CiscoDiscoveryProtocolValue
}

// LayerType returns gopacket.LayerTypeCiscoDiscoveryProtocol.
func (c *CiscoDiscoveryProtocol) LayerType() gopacket.LayerType {
	return LayerTypeCiscoDiscoveryProtocol
}

// CiscoDiscoveryProtocolValue is a TLV value inside a CiscoDiscoveryProtocol packet layer.
type CiscoDiscoveryProtocolValue struct {
	Type   CiscoDiscoveryProtocolType
	Length uint16
	Value  []byte
}

func decodeCiscoDiscoveryProtocol(data []byte) (out gopacket.DecodeResult, err error) {
	c := &CiscoDiscoveryProtocol{
		Version:  data[0],
		TTL:      data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
	}
	if c.Version != 1 {
		err = fmt.Errorf("Invalid CiscoDiscoveryProtocol version number %d", c.Version)
		return
	}
	vData := data[4:]
	for len(vData) > 0 {
		val := CiscoDiscoveryProtocolValue{
			Type:   CiscoDiscoveryProtocolType(binary.BigEndian.Uint16(vData[:2])),
			Length: binary.BigEndian.Uint16(vData[2:4]),
		}
		if val.Length < 4 {
			err = fmt.Errorf("Invalid CiscoDiscoveryProtocol value length %d", val.Length)
			return
		}
		val.Value = vData[4:val.Length]
		c.Values = append(c.Values, val)
		vData = vData[val.Length:]
	}
	c.contents = data
	out.DecodedLayer = c
	return
}
