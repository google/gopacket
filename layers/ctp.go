// Copyright 2012 Google, Inc. All rights reserved.

package layers

import (
	"encoding/binary"
	"fmt"
	"github.com/gconnell/gopacket"
)

// CTPFunction is the function code used by the CTP protocol to identify each
// CTP layer.
type CTPFunction uint16

const (
	CTPFunctionReply       CTPFunction = 1
	CTPFunctionForwardData CTPFunction = 2
)

// CTP implements the CTP protocol, see http://www.mit.edu/people/jhawk/ctp.html.
// We split CTP up into the top-level CTP layer, followed by zero or more
// CTPForwardData layers, followed by a final CTPReply layer.
type CTP struct {
	baseLayer
	SkipCount uint16
}

// LayerType returns gopacket.LayerTypeCTP.
func (c *CTP) LayerType() gopacket.LayerType { return LayerTypeCTP }

// CTPForwardData is the ForwardData layer inside CTP.  See CTP's docs for more
// details.
type CTPForwardData struct {
	baseLayer
	Function       CTPFunction
	ForwardAddress []byte
}

// LayerType returns gopacket.LayerTypeCTPForwardData.
func (c *CTPForwardData) LayerType() gopacket.LayerType { return LayerTypeCTPForwardData }

// ForwardEndpoint returns the CTPForwardData ForwardAddress as an endpoint.
func (c *CTPForwardData) ForwardEndpoint() gopacket.Endpoint {
	return gopacket.NewEndpoint(EndpointMAC, c.ForwardAddress)
}

// CTPReply is the Reply layer inside CTP.  See CTP's docs for more details.
type CTPReply struct {
	baseLayer
	Function      CTPFunction
	ReceiptNumber uint16
	Data          []byte
}

// LayerType returns gopacket.LayerTypeCTPReply.
func (c *CTPReply) LayerType() gopacket.LayerType { return LayerTypeCTPReply }

// Payload returns the CTP reply's Data bytes.
func (c *CTPReply) Payload() []byte { return c.Data }

func decodeCTP(data []byte) (out gopacket.DecodeResult, err error) {
	c := &CTP{
		SkipCount: binary.LittleEndian.Uint16(data[:2]),
		baseLayer: baseLayer{data[:2], data[2:]},
	}
	if c.SkipCount%2 != 0 {
		err = fmt.Errorf("CTP skip count is odd: %d", c.SkipCount)
		return
	}
	out.DecodedLayer = c
	out.NextDecoder = gopacket.DecodeFunc(decodeCTPFromFunctionType)
	return
}

// decodeCTPFromFunctionType reads in the first 2 bytes to determine the CTP
// layer type to decode next, then decodes based on that.
func decodeCTPFromFunctionType(data []byte) (out gopacket.DecodeResult, err error) {
	function := CTPFunction(binary.LittleEndian.Uint16(data[:2]))
	switch function {
	case CTPFunctionReply:
		reply := &CTPReply{
			Function:      function,
			ReceiptNumber: binary.LittleEndian.Uint16(data[2:4]),
			Data:          data[4:],
			baseLayer:     baseLayer{data, nil},
		}
		out.DecodedLayer = reply
		out.ApplicationLayer = reply
		return
	case CTPFunctionForwardData:
		out.DecodedLayer = &CTPForwardData{
			Function:       function,
			ForwardAddress: data[2:8],
			baseLayer:      baseLayer{data[:8], data[8:]},
		}
		out.NextDecoder = gopacket.DecodeFunc(decodeCTPFromFunctionType)
		return
	}
	err = fmt.Errorf("Unknown CTP function type %v", function)
	return
}
