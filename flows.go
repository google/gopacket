// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"fmt"
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
	err = fmt.Errorf("Invalid IP byte string has size %d", len(a))
	return
}

type Flow struct {
	typ      LayerType
	src, dst string
}

func NewFlow(src, dst Endpoint) (_ Flow, err error) {
	if src.typ != dst.typ {
		err = fmt.Errorf("Mismatched endpoint types: %s->%s", src.typ, dst.typ)
		return
	}
	return Flow{src.typ, src.raw, dst.raw}, nil
}
func (f Flow) Endpoints() (src, dst Endpoint) {
	return Endpoint{f.typ, f.src}, Endpoint{f.typ, f.dst}
}
func (f Flow) Src() (src Endpoint) {
	src, _ = f.Endpoints()
	return
}
func (f Flow) Dst() (dst Endpoint) {
	_, dst = f.Endpoints()
	return
}

func (a Endpoint) String() string {
	switch a.typ {
	case LayerTypeIPv4:
		fallthrough
	case LayerTypeIPv6:
		return net.IP([]byte(a.raw)).String()
	case LayerTypeEthernet:
		return net.HardwareAddr([]byte(a.raw)).String()
	case LayerTypeTCP:
		return strconv.Itoa(int(binary.BigEndian.Uint16([]byte(a.raw))))
	case LayerTypePPP:
		return "point"
	}
	return "endpoint"
}

