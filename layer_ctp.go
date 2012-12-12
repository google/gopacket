// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"fmt"
	"net"
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
	SkipCount uint16
}

// LayerType returns LayerTypeCTP.
func (c *CTP) LayerType() LayerType { return LayerTypeCTP }

// CTPForwardData is the ForwardData layer inside CTP.  See CTP's docs for more
// details.
type CTPForwardData struct {
	Function       CTPFunction
	ForwardAddress []byte
}

// LayerType returns LayerTypeCTPForwardData.
func (c *CTPForwardData) LayerType() LayerType { return LayerTypeCTPForwardData }

// ForwardEndpoint returns the CTPForwardData ForwardAddress as an endpoint.
func (c *CTPForwardData) ForwardEndpoint() (e Endpoint) {
	e, _ = NewMACEndpoint(net.HardwareAddr(c.ForwardAddress))
	return
}

// CTPReply is the Reply layer inside CTP.  See CTP's docs for more details.
type CTPReply struct {
	Function      CTPFunction
	ReceiptNumber uint16
	Data          []byte
}

// LayerType returns LayerTypeCTPReply.
func (c *CTPReply) LayerType() LayerType { return LayerTypeCTPReply }

// Payload returns the CTP reply's Data bytes.
func (c *CTPReply) Payload() []byte { return c.Data }

func decodeCTP(data []byte) (out DecodeResult, err error) {
	c := &CTP{
		SkipCount: binary.LittleEndian.Uint16(data[:2]),
	}
	if c.SkipCount%2 != 0 {
		err = fmt.Errorf("CTP skip count is odd: %d", c.SkipCount)
		return
	}
	out.DecodedLayer = c
	out.NextDecoder = decoderFunc(decodeCTPFromFunctionType)
	out.RemainingBytes = data[2:]
	return
}

// decodeCTPFromFunctionType reads in the first 2 bytes to determine the CTP
// layer type to decode next, then decodes based on that.
func decodeCTPFromFunctionType(data []byte) (out DecodeResult, err error) {
	function := CTPFunction(binary.LittleEndian.Uint16(data[:2]))
	switch function {
	case CTPFunctionReply:
		reply := &CTPReply{
			Function:      function,
			ReceiptNumber: binary.LittleEndian.Uint16(data[2:4]),
			Data:          data[4:],
		}
		out.DecodedLayer = reply
		out.ApplicationLayer = reply
		return
	case CTPFunctionForwardData:
		out.DecodedLayer = &CTPForwardData{
			Function:       function,
			ForwardAddress: data[2:8],
		}
		out.NextDecoder = decoderFunc(decodeCTPFromFunctionType)
		out.RemainingBytes = data[8:]
		return
	}
	err = fmt.Errorf("Unknown CTP function type %v", function)
	return
}
