// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"encoding/binary"
	"net"
	"strconv"
)

// Endpoint is the set of bytes used to address packets at various layers.
// See LinkLayer, NetworkLayer, and TransportLayer specifications.
type Endpoint struct {
	typ LayerType
	raw string
}

func (e Endpoint) LayerType() LayerType { return e.typ }
func (e Endpoint) Raw() []byte          { return []byte(e.raw) }
func EndpointFromIP(a net.IP) (_ Endpoint, err error) {
	if len(a) == 4 {
		return Endpoint{LayerTypeIPv4, string(a)}, nil
	} else if len(a) == 16 {
		return Endpoint{LayerTypeIPv6, string(a)}, nil
	}
	return nil, fmt.Errorf("Invalid IP byte string has size %d", len(a))
}

type Flow struct {
	typ      LayerType
	src, dst string
}

func NewFlow(src, dst Endpoint) (_ Flow, err error) {
	if src.Type != dst.Type {
		err = fmt.Errorf("Mismatched endpoint types: %s->%s", src.Type, dst.Type)
		return
	}
	return Flow{src.typ, src.raw, dst.raw}
}
func (f Flow) Endpoints() (src, dst Endpoint) {
	return Endpoint{f.typ, f.src}, Endpoint{f.typ, f.dst}
}

func (a Endpoint) String() string {
	switch a.Type {
	case LayerTypeIPv4:
		fallthrough
	case LayerTypeIPv6:
		return net.IP([]byte(a.Raw)).String()
	case LayerTypeEthernet:
		return net.HardwareAddr([]byte(a.Raw)).String()
	case LayerTypeTCP:
		return strconv.Itoa(int(binary.BigEndian.Uint16([]byte(a.Raw))))
	case LayerTypePPP:
		return "point"
	}
	return "endpoint"
}

