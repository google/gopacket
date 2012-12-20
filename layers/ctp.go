// Copyright 2012 Google, Inc. All rights reserved.

package layers

import (
	"encoding/binary"
	"fmt"
	"github.com/gconnell/gopacket"
)

// EthernetCTPFunction is the function code used by the EthernetCTP protocol to identify each
// EthernetCTP layer.
type EthernetCTPFunction uint16

const (
	EthernetCTPFunctionReply       EthernetCTPFunction = 1
	EthernetCTPFunctionForwardData EthernetCTPFunction = 2
)

// EthernetCTP implements the EthernetCTP protocol, see http://www.mit.edu/people/jhawk/ctp.html.
// We split EthernetCTP up into the top-level EthernetCTP layer, followed by zero or more
// EthernetCTPForwardData layers, followed by a final EthernetCTPReply layer.
type EthernetCTP struct {
	baseLayer
	SkipCount uint16
}

// LayerType returns gopacket.LayerTypeEthernetCTP.
func (c *EthernetCTP) LayerType() gopacket.LayerType {
	return LayerTypeEthernetCTP
}

// EthernetCTPForwardData is the ForwardData layer inside EthernetCTP.  See EthernetCTP's docs for more
// details.
type EthernetCTPForwardData struct {
	baseLayer
	Function       EthernetCTPFunction
	ForwardAddress []byte
}

// LayerType returns gopacket.LayerTypeEthernetCTPForwardData.
func (c *EthernetCTPForwardData) LayerType() gopacket.LayerType {
	return LayerTypeEthernetCTPForwardData
}

// ForwardEndpoint returns the EthernetCTPForwardData ForwardAddress as an endpoint.
func (c *EthernetCTPForwardData) ForwardEndpoint() gopacket.Endpoint {
	return gopacket.NewEndpoint(EndpointMAC, c.ForwardAddress)
}

// EthernetCTPReply is the Reply layer inside EthernetCTP.  See EthernetCTP's docs for more details.
type EthernetCTPReply struct {
	baseLayer
	Function      EthernetCTPFunction
	ReceiptNumber uint16
	Data          []byte
}

// LayerType returns gopacket.LayerTypeEthernetCTPReply.
func (c *EthernetCTPReply) LayerType() gopacket.LayerType {
	return LayerTypeEthernetCTPReply
}

// Payload returns the EthernetCTP reply's Data bytes.
func (c *EthernetCTPReply) Payload() []byte { return c.Data }

func decodeEthernetCTP(data []byte) (out gopacket.DecodeResult, err error) {
	c := &EthernetCTP{
		SkipCount: binary.LittleEndian.Uint16(data[:2]),
		baseLayer: baseLayer{data[:2], data[2:]},
	}
	if c.SkipCount%2 != 0 {
		err = fmt.Errorf("EthernetCTP skip count is odd: %d", c.SkipCount)
		return
	}
	out.DecodedLayer = c
	out.NextDecoder = gopacket.DecodeFunc(decodeEthernetCTPFromFunctionType)
	return
}

// decodeEthernetCTPFromFunctionType reads in the first 2 bytes to determine the EthernetCTP
// layer type to decode next, then decodes based on that.
func decodeEthernetCTPFromFunctionType(data []byte) (out gopacket.DecodeResult, err error) {
	function := EthernetCTPFunction(binary.LittleEndian.Uint16(data[:2]))
	switch function {
	case EthernetCTPFunctionReply:
		reply := &EthernetCTPReply{
			Function:      function,
			ReceiptNumber: binary.LittleEndian.Uint16(data[2:4]),
			Data:          data[4:],
			baseLayer:     baseLayer{data, nil},
		}
		out.DecodedLayer = reply
		out.ApplicationLayer = reply
		return
	case EthernetCTPFunctionForwardData:
		forward := &EthernetCTPForwardData{
			Function:       function,
			ForwardAddress: data[2:8],
			baseLayer:      baseLayer{data[:8], data[8:]},
		}
		out.DecodedLayer = forward
		out.NextDecoder = gopacket.DecodeFunc(decodeEthernetCTPFromFunctionType)
		return
	}
	err = fmt.Errorf("Unknown EthernetCTP function type %v", function)
	return
}
