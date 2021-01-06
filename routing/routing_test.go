// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// +build linux

package routing

import (
	"net"
	"sort"
	"testing"
)

var testRouter router

func init() {
	testRouter = router{ifaces: make(map[int]*net.Interface), addrs: make(map[int]ipAddrs)}
	// Configure default route
	defaultHW, _ := net.ParseMAC("01:23:45:67:89:ab")
	defaultInterface := net.Interface{Index: 5, MTU: 1500, Name: "Default", HardwareAddr: defaultHW, Flags: 1}
	testRouter.ifaces[2] = &defaultInterface
	testRouter.addrs[2] = ipAddrs{v4: net.IPv4(192, 168, 1, 2)}
	defaultRoute := &rtInfo{Gateway: net.IPv4(192, 168, 1, 1), InputIface: 0, OutputIface: 2, Priority: 600}
	testRouter.v4 = append(testRouter.v4, defaultRoute)
	// Configure local route
	localHW, _ := net.ParseMAC("01:23:45:67:89:ac")
	localInterface := net.Interface{Index: 1, MTU: 1500, Name: "Local", HardwareAddr: localHW, Flags: 1}
	testRouter.ifaces[1] = &localInterface
	testRouter.addrs[1] = ipAddrs{v4: net.IPv4(10, 0, 0, 2)}
	localRoute := &rtInfo{Dst: &net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		Gateway: net.IPv4(10, 0, 0, 1), InputIface: 0, OutputIface: 1, Priority: 300}
	testRouter.v4 = append(testRouter.v4, localRoute)
	sort.Sort(testRouter.v4)
}

var routeTests = []struct {
	dst       net.IP
	ifaceName string
}{
	{net.IPv4(8, 8, 8, 8), "Default"},
	{net.IPv4(192, 168, 2, 3), "Default"},
	{net.IPv4(10, 0, 0, 3), "Local"},
}

func TestRoute(t *testing.T) {
	for _, tt := range routeTests {
		t.Run(tt.dst.String(), func(t *testing.T) {
			iface, _, _, _ := testRouter.Route(tt.dst)
			if tt.ifaceName != iface.Name {
				t.Fatalf("test %s\n want:%s\n got:%s\n", tt.dst.String(), tt.ifaceName, iface.Name)
			}
		})
	}
}
