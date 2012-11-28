// Copyright (c) 2012 Graeme Connell. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"errors"
)

// FlowKey is a hashable struct that associates a packet with its unique
// flow.  This is built for speed, not human-readability, so printing out this
// struct may be uninformative.
type FlowKey struct {
	netType, transType             LayerType
	srcNet, dstNet, srcApp, dstApp string
}

// One side of a flow key
type FlowAddress struct {
	netType, transType LayerType
	net, app           string
}

// NewFlowKey creates a new FlowKey from a Network and Transport layer,
// guaranteed to succeed.
func NewFlowKey(net NetworkLayer, trans TransportLayer) FlowKey {
	return FlowKey{
		netType:   net.LayerType(),
		transType: trans.LayerType(),
		srcNet:    string(net.SrcNetAddr().Raw()),
		dstNet:    string(net.DstNetAddr().Raw()),
		srcApp:    string(trans.SrcAppAddr().Raw()),
		dstApp:    string(trans.DstAppAddr().Raw()),
	}
}

// Src returns the source address of a FlowKey.
func (f *FlowKey) Src() FlowAddress {
	return FlowAddress{
		netType:   f.netType,
		transType: f.transType,
		net:       f.srcNet,
		app:       f.srcApp,
	}
}

// Dst returns the destination address of a FlowKey.
func (f *FlowKey) Dst() FlowAddress {
	return FlowAddress{
		netType:   f.netType,
		transType: f.transType,
		net:       f.dstNet,
		app:       f.dstApp,
	}
}

// FlowKeyFromAddresses combines a src and dst FlowAddress into a single
// FlowKey.  The network and transport types of the original FlowAddresses must
// match, or this function returns an error.
func FlowKeyFromAddresses(src, dst FlowAddress) (f FlowKey, err error) {
	if src.netType != dst.netType {
		err = errors.New("Flow key network types do not match")
		return
	}
	if src.transType != dst.transType {
		err = errors.New("Flow key transport types do not match")
		return
	}
	return FlowKey{
		netType:   src.netType,
		transType: src.transType,
		srcNet:    src.net,
		srcApp:    src.app,
		dstNet:    dst.net,
		dstApp:    dst.app,
	}, nil
}
