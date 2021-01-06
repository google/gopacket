package routing

import (
	"fmt"
	"net"
	"testing"
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
