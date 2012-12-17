// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	//"encoding/binary"
	"fmt"
	//"net"
	//"strconv"
)

// Endpoint is the set of bytes used to address packets at various layers.
// See LinkLayer, NetworkLayer, and TransportLayer specifications.
// Endpoints are usable as map keys.
type Endpoint struct {
	typ LayerType
	raw string
}

// LayerType returns the layer type associated with this endpoint.
func (e Endpoint) LayerType() LayerType { return e.typ }

// Raw returns the raw bytes of this endpoint.  These aren't human-readable
// most of the time, but they are faster than calling String.
func (e Endpoint) Raw() []byte { return []byte(e.raw) }

// LessThan provides a stable ordering for all endpoints.  It sorts first based
// on the LayerType of an endpoint, then based on the raw bytes of that endpoint.
// For some endpoints, the actual comparison may not make sense, however this
// ordering does provide useful information for most Endpoint types.
func (a Endpoint) LessThan(b Endpoint) bool {
	return a.typ < b.typ || (a.typ == b.typ && a.raw < b.raw)
}

// String returns the endpoint as a human-readable string.
func (a Endpoint) String() string {
	return fmt.Sprintf("%v:%v", a.typ, a.raw)
}

/*
// NewIPEndpoint creates a new IPv4 or IPv6 endpoint from a net.IP address.
func NewIPEndpoint(a net.IP) (_ Endpoint, err error) {
	if len(a) == 4 {
		return Endpoint{LayerTypeIPv4, string(a)}, nil
	} else if len(a) == 16 {
		return Endpoint{LayerTypeIPv6, string(a)}, nil
	}
	err = fmt.Errorf("Invalid IP byte string has size %v", len(a))
	return
}

// NewMACEndpoint creates a new Ethernet endpoint from a net.HardwareAddr address.
func NewMACEndpoint(a net.HardwareAddr) (_ Endpoint, err error) {
	if len(a) == 6 {
		return Endpoint{LayerTypeEthernet, string(a)}, nil
	}
	err = fmt.Errorf("Invalid MAC byte string has size %v", len(a))
	return
}

// NewTCPPortEndpoint creates a new TCP endpoint.
func NewTCPPortEndpoint(a uint16) Endpoint {
	return Endpoint{LayerTypeTCP, string([]byte{byte(a >> 8), byte(a)})}
}

// NewUDPPortEndpoint creates a new UDP endpoint.
func NewUDPPortEndpoint(a uint16) Endpoint {
	return Endpoint{LayerTypeUDP, string([]byte{byte(a >> 8), byte(a)})}
}

// NewSCTPPortEndpoint creates a new SCTP endpoint.
func NewSCTPPortEndpoint(a uint16) Endpoint {
	return Endpoint{LayerTypeSCTP, string([]byte{byte(a >> 8), byte(a)})}
}

// PPPEndpoint is an "endpoint" for PPP flows.  Since PPP is "point to point", we have a single endpoint "point"
// that we use in all cases for PPP.
var PPPEndpoint = Endpoint{typ: LayerTypePPP}
*/
// Flow represents the direction of traffic for a packet layer, as a source and destination Endpoint.
// Flows are usable as map keys.
type Flow struct {
	typ      LayerType
	src, dst string
}

// NewFlow creates a new flow by pasting together two endpoints.  The endpoints must
// have the same LayerType, or this function will return an error.
func NewFlow(src, dst Endpoint) (_ Flow, err error) {
	if src.typ != dst.typ {
		err = fmt.Errorf("Mismatched endpoint types: %v->%v", src.typ, dst.typ)
		return
	}
	return Flow{src.typ, src.raw, dst.raw}, nil
}

// String returns a human-readable representation of this flow, in the form
// "Src->Dst"
func (f Flow) String() string {
	return fmt.Sprintf("%v->%v", f.src, f.dst)
}

// LayerType returns the LayerType for this Flow.
func (f Flow) LayerType() LayerType {
	return f.typ
}

// Endpoints returns the two Endpoints for this flow.
func (f Flow) Endpoints() (src, dst Endpoint) {
	return Endpoint{f.typ, f.src}, Endpoint{f.typ, f.dst}
}

// Src returns the source Endpoint for this flow.
func (f Flow) Src() (src Endpoint) {
	src, _ = f.Endpoints()
	return
}

// Dst returns the destination Endpoint for this flow.
func (f Flow) Dst() (dst Endpoint) {
	_, dst = f.Endpoints()
	return
}

// Reverse returns a new flow with endpoints reversed.
func (f Flow) Reverse() Flow {
	return Flow{f.typ, f.dst, f.src}
}

/*
// PPPFlow is a "flow" for PPP.  Since PPP is "point to point", we have a single constant flow "point"->"point".
var PPPFlow = Flow{typ: LayerTypePPP}
*/
