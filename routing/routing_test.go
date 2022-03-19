// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// +build linux

package routing

import (
	"fmt"
	"net"
	"runtime"
	"sort"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestPrivateRoute(t *testing.T) {
	tests := []struct {
		name                          string
		router                        router
		routes                        routeSlice
		input                         net.HardwareAddr
		src, dst                      net.IP
		wantIface                     int
		wantGateway, wantPreferredSrc net.IP
		wantErr                       error
	}{
		{
			name: "only static routes",
			router: router{
				ifaces: map[int]*net.Interface{
					1: {
						Index:        1,
						MTU:          1500,
						Name:         "eth0",
						HardwareAddr: net.HardwareAddr{0x54, 0x52, 0x00, 0x00, 0x00, 0x01},
						Flags:        net.FlagUp,
					},
					2: {
						Index:        2,
						MTU:          1500,
						Name:         "eth1",
						HardwareAddr: net.HardwareAddr{0x54, 0x52, 0x00, 0x00, 0x00, 0x02},
						Flags:        net.FlagUp,
					},
				},
				addrs: map[int]ipAddrs{
					1: {
						v4: net.ParseIP("192.168.10.1/24"),
					},
					2: {
						v4: net.ParseIP("192.168.20.1/24"),
					},
				},
			},
			routes: []*rtInfo{
				{
					Dst: &net.IPNet{
						IP:   net.ParseIP("192.168.10.0"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
					PrefSrc:     net.ParseIP("192.168.10.1"),
					OutputIface: 1,
				},
				{
					Dst: &net.IPNet{
						IP:   net.ParseIP("192.168.20.0"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
					PrefSrc:     net.ParseIP("192.168.20.1"),
					OutputIface: 2,
				},
			},
			input:            net.HardwareAddr{0x54, 0x52, 0x00, 0x00, 0x00, 0x01},
			src:              net.ParseIP("192.168.10.1"),
			dst:              net.ParseIP("192.168.20.1"),
			wantIface:        2,
			wantGateway:      nil,
			wantPreferredSrc: net.ParseIP("192.168.20.1"),
			wantErr:          nil,
		},
		{
			name: "not exists route with default gateway",
			router: router{
				ifaces: map[int]*net.Interface{
					1: {
						Index:        1,
						MTU:          1500,
						Name:         "eth0",
						HardwareAddr: net.HardwareAddr{0x54, 0x52, 0x00, 0x00, 0x00, 0x01},
						Flags:        net.FlagUp,
					},
					2: {
						Index:        2,
						MTU:          1500,
						Name:         "eth1",
						HardwareAddr: net.HardwareAddr{0x54, 0x52, 0x00, 0x00, 0x00, 0x02},
						Flags:        net.FlagUp,
					},
				},
				addrs: map[int]ipAddrs{
					1: {
						v4: net.ParseIP("192.168.10.1/24"),
					},
					2: {
						v4: net.ParseIP("192.168.20.1/24"),
					},
				},
			},
			routes: []*rtInfo{
				{
					Gateway:     net.ParseIP("192.168.20.254"),
					PrefSrc:     net.ParseIP("192.168.20.1"),
					OutputIface: 2,
				},
				{
					Dst: &net.IPNet{
						IP:   net.ParseIP("192.168.10.0"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
					PrefSrc:     net.ParseIP("192.168.10.1"),
					OutputIface: 1,
				},
				{
					Dst: &net.IPNet{
						IP:   net.ParseIP("192.168.20.0"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
					PrefSrc:     net.ParseIP("192.168.20.1"),
					OutputIface: 2,
				},
			},
			input:            net.HardwareAddr{0x54, 0x52, 0x00, 0x00, 0x00, 0x01},
			src:              net.ParseIP("192.168.10.1"),
			dst:              net.ParseIP("192.168.30.2"),
			wantIface:        2,
			wantGateway:      net.ParseIP("192.168.20.254"),
			wantPreferredSrc: net.ParseIP("192.168.20.1"),
			wantErr:          nil,
		},
		{
			name: "exists route with default gateway",
			router: router{
				ifaces: map[int]*net.Interface{
					1: {
						Index:        1,
						MTU:          1500,
						Name:         "eth0",
						HardwareAddr: net.HardwareAddr{0x54, 0x52, 0x00, 0x00, 0x00, 0x01},
						Flags:        net.FlagUp,
					},
					2: {
						Index:        2,
						MTU:          1500,
						Name:         "eth1",
						HardwareAddr: net.HardwareAddr{0x54, 0x52, 0x00, 0x00, 0x00, 0x02},
						Flags:        net.FlagUp,
					},
				},
				addrs: map[int]ipAddrs{
					1: {
						v4: net.ParseIP("192.168.10.1/24"),
					},
					2: {
						v4: net.ParseIP("192.168.20.1/24"),
					},
				},
			},
			routes: []*rtInfo{
				{
					Gateway:     net.ParseIP("192.168.20.254"),
					PrefSrc:     net.ParseIP("192.168.20.1"),
					OutputIface: 2,
				},
				{
					Dst: &net.IPNet{
						IP:   net.ParseIP("192.168.10.0"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
					PrefSrc:     net.ParseIP("192.168.10.1"),
					OutputIface: 1,
				},
				{
					Dst: &net.IPNet{
						IP:   net.ParseIP("192.168.20.0"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
					PrefSrc:     net.ParseIP("192.168.20.1"),
					OutputIface: 2,
				},
			},
			input:            net.HardwareAddr{0x54, 0x52, 0x00, 0x00, 0x00, 0x01},
			src:              net.ParseIP("192.168.10.1"),
			dst:              net.ParseIP("192.168.20.2"),
			wantIface:        2,
			wantGateway:      nil,
			wantPreferredSrc: net.ParseIP("192.168.20.1"),
			wantErr:          nil,
		},
		{
			name: "not exists route without default gateway",
			router: router{
				ifaces: map[int]*net.Interface{
					1: {
						Index:        1,
						MTU:          1500,
						Name:         "eth0",
						HardwareAddr: net.HardwareAddr{0x54, 0x52, 0x00, 0x00, 0x00, 0x01},
						Flags:        net.FlagUp,
					},
					2: {
						Index:        2,
						MTU:          1500,
						Name:         "eth1",
						HardwareAddr: net.HardwareAddr{0x54, 0x52, 0x00, 0x00, 0x00, 0x02},
						Flags:        net.FlagUp,
					},
				},
				addrs: map[int]ipAddrs{
					1: {
						v4: net.ParseIP("192.168.10.1/24"),
					},
					2: {
						v4: net.ParseIP("192.168.20.1/24"),
					},
				},
			},
			routes: []*rtInfo{
				{
					Dst: &net.IPNet{
						IP:   net.ParseIP("192.168.10.0"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
					PrefSrc:     net.ParseIP("192.168.10.1"),
					OutputIface: 1,
				},
				{
					Dst: &net.IPNet{
						IP:   net.ParseIP("192.168.20.0"),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
					PrefSrc:     net.ParseIP("192.168.20.1"),
					OutputIface: 2,
				},
			},
			input:            net.HardwareAddr{0x54, 0x52, 0x00, 0x00, 0x00, 0x01},
			src:              net.ParseIP("192.168.10.1"),
			dst:              net.ParseIP("192.168.30.2"),
			wantIface:        2,
			wantGateway:      nil,
			wantPreferredSrc: nil,
			wantErr:          fmt.Errorf("no route found for 192.168.30.2"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface, gateway, preferredSrc, err := tt.router.route(tt.routes, tt.input, tt.src, tt.dst)
			if tt.wantErr != nil {
				if err != nil && tt.wantErr.Error() == err.Error() {
					return
				}
				t.Errorf("route() illegal return value `err`:\ngot	:%#v\n\nwant:	%#v\n\n", err, tt.wantErr)

			}
			if err != nil {
				t.Errorf("route() illegal return value `err`:\ngot	:%#v\n\nwant:	nil\n\n", err)
			}

			if tt.wantIface != iface {
				t.Errorf("route() illegal return value `iface`:\ngot	:%d\n\nwant:	%d\n\n", iface, tt.wantIface)
			}

			if !tt.wantGateway.Equal(gateway) {
				t.Errorf("route() illegal return value `gateway`:\ngot	:%#v\n\nwant	:%#v\n\n", gateway, tt.wantGateway)
			}

			if !tt.wantPreferredSrc.Equal(preferredSrc) {
				t.Errorf("route() illegal return value `preferredSrc`:\ngot	:%#v\n\nwant	:%#v\n\n", preferredSrc, tt.wantPreferredSrc)
			}

		})
	}

}

func TestRouting(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// parent network namespace
	testNs, _ := netns.New()
	defer testNs.Close()

	// child network namespace
	newns, _ := netns.New()
	defer newns.Close()

	veth0 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: "veth0",
		},
		PeerName: "veth0-peer",
	}

	veth1 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: "veth1",
		},
		PeerName: "veth1-peer",
	}

	// ip link add veth0 type veth peer name veth0-peer
	if err := netlink.LinkAdd(veth0); err != nil {
		t.Errorf("\nFailed SetUp Test Environment: link add veth0 type veth peer name veth0-peer: %#v\n\n", err)
		return
	}

	// ip link add veth1 type veth peer name veth1-peer
	if err := netlink.LinkAdd(veth1); err != nil {
		t.Errorf("\nFailed SetUp Test Environment: link add veth1 type veth peer name veth1-peer: %#v\n\n", err)
		return
	}

	// ip address add 192.168.10.1/24 dev veth0
	veth0Addr, err := netlink.ParseAddr("192.168.10.1/24")
	if err != nil {
		t.Errorf("\nFailed SetUp Test Environment: parse addr 192.168.10.1/24: %#v\n\n", err)
		return
	}
	if err := netlink.AddrAdd(veth0, veth0Addr); err != nil {
		t.Errorf("\nFailed SetUp Test Environment: address add 192.168.10.1/24 dev veth0: %#v\n\n", err)
		return
	}

	// ip address add 192.168.20.1/24 dev veth1
	veth1Addr, err := netlink.ParseAddr("192.168.20.1/24")
	if err != nil {
		t.Errorf("\nFailed SetUp Test Environment: parse addr 192.168.20.1/24: %#v\n\n", err)
		return
	}
	if err := netlink.AddrAdd(veth1, veth1Addr); err != nil {
		t.Errorf("\nFailed SetUp Test Environment: parse addr 192.168.20.1/24 dev veth1: %#v\n\n", err)
		return
	}

	// ip link set up veth0
	if err := netlink.LinkSetUp(veth0); err != nil {
		t.Errorf("\nFailed SetUp Test Environment: link set up veth0: %#v\n\n", err)
		return
	}

	// ip link set up veth1
	if err := netlink.LinkSetUp(veth1); err != nil {
		t.Errorf("\nFailed SetUp Test Environment: link set up veth1: %#v\n\n", err)
		return
	}

	veth0Peer, err := netlink.LinkByName("veth0-peer")
	if err != nil {
		t.Errorf("\nFailed SetUp Test Environment: link by name veth0-peer: %#v\n\n", err)
		return
	}
	// ip link set up veth0-peer
	if err := netlink.LinkSetUp(veth0Peer); err != nil {
		t.Errorf("\nFailed SetUp Test Environment: link set up veth0-peer: %#v\n\n", err)
		return
	}
	// ip link set dev veth0-peer netns {testNs}
	if err := netlink.LinkSetNsFd(veth0Peer, int(testNs)); err != nil {
		t.Errorf("\nFailed SetUp Test Environment: link set dev veth0-peer netns testNs: %#v\n\n", err)
		return
	}

	veth1Peer, err := netlink.LinkByName("veth1-peer")
	if err != nil {
		t.Errorf("\nFailed SetUp Test Environment: link by name veth1-peer: %#v\n\n", err)
		return
	}
	// ip link set up veth1-peer
	if err := netlink.LinkSetUp(veth1Peer); err != nil {
		t.Errorf("\nFailed SetUp Test Environment: link set up veth1-peer: %#v\n\n", err)
		return
	}
	// ip link set dev veth1-peer netns {testNs}
	if err := netlink.LinkSetNsFd(veth1Peer, int(testNs)); err != nil {
		t.Errorf("\nFailed SetUp Test Environment: link set dev veth1-peer netns testNs: %#v\n\n", err)
		return
	}

	/**
	 * routing table
	 * 192.168.10.0/24 dev veth0 proto kernel scope link src 192.168.10.1
	 * 192.168.20.0/24 dev veth1 proto kernel scope link src 192.168.20.1
	 */

	t.Run("exists route without default gateway", func(t *testing.T) {
		netns.Set(newns)
		r, err := New()
		if err != nil {
			t.Errorf("\ngot:	%#v\nwant:	nil", err)
			return
		}

		iface, _, _, err := r.Route(net.ParseIP("192.168.10.2"))
		if err != nil {
			t.Errorf("\ngot:	%#v\nwant:	nil", err)
		}

		if veth0.Index != iface.Index {
			t.Errorf("\ngot:	%d\nwant:	%d\n\n", iface.Index, veth0.Index)
		}

		iface, _, _, err = r.Route(net.ParseIP("192.168.20.2"))
		if err != nil {
			t.Errorf("\ngot:	%#v\nwant:	nil", err)
		}

		if veth1.Index != iface.Index {
			t.Errorf("\ngot:	%d\nwant:	%d\n\n", iface.Index, veth1.Index)
		}
	})

	t.Run("not exists route without default gateway", func(t *testing.T) {
		netns.Set(newns)

		r, err := New()
		if err != nil {
			t.Errorf("\ngot:	%#v\nwant:	nil\n\n", err)
			return
		}

		if _, _, _, err = r.Route(net.ParseIP("172.16.0.1")); err == nil && err == fmt.Errorf("no route found for 172.16.0.1") {
			t.Errorf("\ngot:	%#v\nwant:	%#v\n\n", err, fmt.Errorf("no route found for 172.16.0.1"))
			return
		}
	})

	t.Run("exists route with default gateway", func(t *testing.T) {
		netns.Set(newns)

		netlink.RouteAdd(&netlink.Route{
			Gw:        net.ParseIP("192.168.20.254"),
			LinkIndex: veth1.Index,
		})
		defer func() {
			// teardown
			netlink.RouteDel(&netlink.Route{
				Gw:        net.ParseIP("192.168.20.254"),
				LinkIndex: veth1.Index,
			})
		}()

		r, err := New()
		if err != nil {
			t.Errorf("\ngot:	%#v\nwant:	nil\n\n", err)
			return
		}

		iface, gateway, prefSrc, err := r.Route(net.ParseIP("192.168.10.2"))
		if err != nil {
			t.Errorf("\ngot:	%#v\nwant:	nil\n\n", err)
			return
		}

		if veth0.Index != iface.Index {
			t.Errorf("\ngot:	%d\nwant:	%d\n\n", iface.Index, veth0.Index)
		}

		if gateway != nil {
			t.Errorf("\ngot:	%#v\nwant:	nil\n\n", gateway)
		}

		if !prefSrc.Equal(net.ParseIP("192.168.10.1")) {
			t.Errorf("\ngot:	%#v\nwant:	%#v\n\n", prefSrc, net.ParseIP("192.168.10.1"))
		}
	})

	t.Run("not exists route with default gateway", func(t *testing.T) {
		netns.Set(newns)

		netlink.RouteAdd(&netlink.Route{
			Gw:        net.ParseIP("192.168.20.254"),
			LinkIndex: veth1.Index,
		})
		defer func() {
			// teardown
			netlink.RouteDel(&netlink.Route{
				Gw:        net.ParseIP("192.168.20.254"),
				LinkIndex: veth1.Index,
			})
		}()

		r, err := New()
		if err != nil {
			t.Errorf("\ngot:	%#v\nwant:	nil\n\n", err)
			return
		}

		iface, gateway, prefSrc, err := r.Route(net.ParseIP("172.16.0.1"))
		if err != nil {
			t.Errorf("\ngot:	%#v\nwant:	nil\n\n", err)
			return
		}

		if veth1.Index != iface.Index {
			t.Errorf("\ngot:	%d\nwant:	%d\n\n", iface.Index, veth1.Index)
		}

		if !gateway.Equal(net.ParseIP("192.168.20.254")) {
			t.Errorf("\ngot:	%#v\nwant:	%#v\n\n", gateway, net.ParseIP("192.168.20.254"))
		}

		if !prefSrc.Equal(net.ParseIP("192.168.20.1")) {
			t.Errorf("\ngot:	%#v\nwant:	%#v\n\n", prefSrc, net.ParseIP("192.168.20.1"))
		}
	})
}

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
