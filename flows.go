// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	//"encoding/binary"
	"fmt"
	//"net"
	"strconv"
)

// Endpoint is the set of bytes used to address packets at various layers.
// See LinkLayer, NetworkLayer, and TransportLayer specifications.
// Endpoints are usable as map keys.
type Endpoint struct {
	typ EndpointType
	raw string
}

// EndpointType returns the layer type associated with this endpoint.
func (e Endpoint) EndpointType() EndpointType { return e.typ }

// Raw returns the raw bytes of this endpoint.  These aren't human-readable
// most of the time, but they are faster than calling String.
func (e Endpoint) Raw() []byte { return []byte(e.raw) }

// LessThan provides a stable ordering for all endpoints.  It sorts first based
// on the EndpointType of an endpoint, then based on the raw bytes of that endpoint.
// For some endpoints, the actual comparison may not make sense, however this
// ordering does provide useful information for most Endpoint types.
func (a Endpoint) LessThan(b Endpoint) bool {
	return a.typ < b.typ || (a.typ == b.typ && a.raw < b.raw)
}

// NewEndpoint creates a new Endpoint object.
func NewEndpoint(typ EndpointType, raw []byte) Endpoint {
	return Endpoint{typ, string(raw)}
}

type endpointType struct {
	name      string
	formatter func([]byte) string
}

type EndpointType int64

var endpointTypes = map[EndpointType]endpointType{}

func RegisterEndpointType(num int, name string, formatter func([]byte) string) EndpointType {
	t := EndpointType(num)
	if _, ok := endpointTypes[t]; ok {
		panic("Endpoint type number already in use")
	}
	endpointTypes[t] = endpointType{
		name:      name,
		formatter: formatter,
	}
	return t
}

func (e EndpointType) String() string {
	if t, ok := endpointTypes[e]; ok {
		return t.name
	}
	return strconv.Itoa(int(e))
}

func (e Endpoint) String() string {
	if t, ok := endpointTypes[e.typ]; ok {
		return t.formatter([]byte(e.raw))
	}
	return fmt.Sprintf("%v:%v", e.typ, e.raw)
}

// Flow represents the direction of traffic for a packet layer, as a source and destination Endpoint.
// Flows are usable as map keys.
type Flow struct {
	typ      EndpointType
	src, dst string
}

// FlowFromEndpoints creates a new flow by pasting together two endpoints.
// The endpoints must have the same EndpointType, or this function will return
// an error.
func FlowFromEndpoints(src, dst Endpoint) (_ Flow, err error) {
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

// EndpointType returns the EndpointType for this Flow.
func (f Flow) EndpointType() EndpointType {
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

// NewFlow creates a new flow.
func NewFlow(t EndpointType, src, dst []byte) Flow {
	return Flow{t, string(src), string(dst)}
}
