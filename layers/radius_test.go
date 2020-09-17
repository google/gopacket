// Copyright 2020 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

import (
	"reflect"
	"testing"

	"github.com/google/gopacket"
)

func checkRADIUS(desc string, t *testing.T, packetBytes []byte, pExpectedRADIUS *RADIUS) {
	// Analyse the packet bytes, yielding a new packet object p.
	p := gopacket.NewPacket(packetBytes, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Errorf("Failed to decode packet %s: %v", desc, p.ErrorLayer().Error())
	}

	// Ensure that the packet analysis yielded the correct set of layers:
	//    Link Layer        = Ethernet.
	//    Network Layer     = IPv4.
	//    Transport Layer   = UDP.
	//    Application Layer = RADIUS.
	checkLayers(p, []gopacket.LayerType{
		LayerTypeEthernet,
		LayerTypeIPv4,
		LayerTypeUDP,
		LayerTypeRADIUS,
	}, t)

	// Select the Application (RADIUS) layer.
	pResultRADIUS, ok := p.ApplicationLayer().(*RADIUS)
	if !ok {
		t.Error("No RADIUS layer type found in packet in " + desc + ".")
	}

	// Compare the generated RADIUS object with the expected RADIUS object.
	if !reflect.DeepEqual(pResultRADIUS, pExpectedRADIUS) {
		t.Errorf("RADIUS packet processing failed for packet "+desc+
			":\ngot  :\n%#v\n\nwant :\n%#v\n\n", pResultRADIUS, pExpectedRADIUS)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := pResultRADIUS.SerializeTo(buf, opts)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(pResultRADIUS.BaseLayer.Contents, buf.Bytes()) {
		t.Errorf("RADIUS packet serialization failed for packet "+desc+
			":\ngot  :\n%x\n\nwant :\n%x\n\n", buf.Bytes(), packetBytes)
	}
}

func faliedRADIUS(t *testing.T, desc string, data *RADIUS) {
	t.Run(desc, func(t *testing.T) {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{}
		if err := data.SerializeTo(buf, opts); err != nil {
			t.Error(err)
		}

		p := gopacket.NewPacket(buf.Bytes(), LayerTypeRADIUS, gopacket.Default)
		if p.ErrorLayer() == nil {
			t.Errorf("No Error layer type found in packet in %s.\n", desc)
		}
	})
}

func TestRADIUSCode(t *testing.T) {
	tests := []struct {
		name string
		code RADIUSCode
	}{
		{name: "Unknown(0)", code: RADIUSCode(0)},
		{name: "Access-Request", code: RADIUSCodeAccessRequest},
		{name: "Access-Accept", code: RADIUSCodeAccessAccept},
		{name: "Access-Reject", code: RADIUSCodeAccessReject},
		{name: "Accounting-Request", code: RADIUSCodeAccountingRequest},
		{name: "Accounting-Response", code: RADIUSCodeAccountingResponse},
		{name: "Access-Challenge", code: RADIUSCodeAccessChallenge},
		{name: "Status-Server", code: RADIUSCodeStatusServer},
		{name: "Status-Client", code: RADIUSCodeStatusClient},
		{name: "Reserved", code: RADIUSCodeReserved},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name != tt.code.String() {
				t.Errorf("Failed to convert constrant value to string: %d\n", tt.code)
			}
		})
	}
}

func TestRADIUSAttributeType(t *testing.T) {
	tests := []struct {
		name string
		code RADIUSAttributeType
	}{
		{name: "Unknown(0)", code: RADIUSAttributeType(0)},
		{name: "User-Name", code: RADIUSAttributeTypeUserName},
		{name: "User-Password", code: RADIUSAttributeTypeUserPassword},
		{name: "CHAP-Password", code: RADIUSAttributeTypeCHAPPassword},
		{name: "NAS-IP-Address", code: RADIUSAttributeTypeNASIPAddress},
		{name: "NAS-Port", code: RADIUSAttributeTypeNASPort},
		{name: "Service-Type", code: RADIUSAttributeTypeServiceType},
		{name: "Framed-Protocol", code: RADIUSAttributeTypeFramedProtocol},
		{name: "Framed-IP-Address", code: RADIUSAttributeTypeFramedIPAddress},
		{name: "Framed-IP-Netmask", code: RADIUSAttributeTypeFramedIPNetmask},
		{name: "Framed-Routing", code: RADIUSAttributeTypeFramedRouting},
		{name: "Filter-Id", code: RADIUSAttributeTypeFilterId},
		{name: "Framed-MTU", code: RADIUSAttributeTypeFramedMTU},
		{name: "Framed-Compression", code: RADIUSAttributeTypeFramedCompression},
		{name: "Login-IP-Host", code: RADIUSAttributeTypeLoginIPHost},
		{name: "Login-Service", code: RADIUSAttributeTypeLoginService},
		{name: "Login-TCP-Port", code: RADIUSAttributeTypeLoginTCPPort},
		{name: "Reply-Message", code: RADIUSAttributeTypeReplyMessage},
		{name: "Callback-Number", code: RADIUSAttributeTypeCallbackNumber},
		{name: "Callback-Id", code: RADIUSAttributeTypeCallbackId},
		{name: "Framed-Route", code: RADIUSAttributeTypeFramedRoute},
		{name: "Framed-IPX-Network", code: RADIUSAttributeTypeFramedIPXNetwork},
		{name: "State", code: RADIUSAttributeTypeState},
		{name: "Class", code: RADIUSAttributeTypeClass},
		{name: "Vendor-Specific", code: RADIUSAttributeTypeVendorSpecific},
		{name: "Session-Timeout", code: RADIUSAttributeTypeSessionTimeout},
		{name: "Idle-Timeout", code: RADIUSAttributeTypeIdleTimeout},
		{name: "Termination-Action", code: RADIUSAttributeTypeTerminationAction},
		{name: "Called-Station-Id", code: RADIUSAttributeTypeCalledStationId},
		{name: "Calling-Station-Id", code: RADIUSAttributeTypeCallingStationId},
		{name: "NAS-Identifier", code: RADIUSAttributeTypeNASIdentifier},
		{name: "Proxy-State", code: RADIUSAttributeTypeProxyState},
		{name: "Login-LAT-Service", code: RADIUSAttributeTypeLoginLATService},
		{name: "Login-LAT-Node", code: RADIUSAttributeTypeLoginLATNode},
		{name: "Login-LAT-Group", code: RADIUSAttributeTypeLoginLATGroup},
		{name: "Framed-AppleTalk-Link", code: RADIUSAttributeTypeFramedAppleTalkLink},
		{name: "Framed-AppleTalk-Network", code: RADIUSAttributeTypeFramedAppleTalkNetwork},
		{name: "Framed-AppleTalk-Zone", code: RADIUSAttributeTypeFramedAppleTalkZone},
		{name: "Acct-Status-Type", code: RADIUSAttributeTypeAcctStatusType},
		{name: "Acct-Delay-Time", code: RADIUSAttributeTypeAcctDelayTime},
		{name: "Acct-Input-Octets", code: RADIUSAttributeTypeAcctInputOctets},
		{name: "Acct-Output-Octets", code: RADIUSAttributeTypeAcctOutputOctets},
		{name: "Acct-Session-Id", code: RADIUSAttributeTypeAcctSessionId},
		{name: "Acct-Authentic", code: RADIUSAttributeTypeAcctAuthentic},
		{name: "Acct-Session-Time", code: RADIUSAttributeTypeAcctSessionTime},
		{name: "Acct-Input-Packets", code: RADIUSAttributeTypeAcctInputPackets},
		{name: "Acct-Output-Packets", code: RADIUSAttributeTypeAcctOutputPackets},
		{name: "Acct-Terminate-Cause", code: RADIUSAttributeTypeAcctTerminateCause},
		{name: "Acct-Multi-Session-Id", code: RADIUSAttributeTypeAcctMultiSessionId},
		{name: "Acct-Link-Count", code: RADIUSAttributeTypeAcctLinkCount},
		{name: "Acct-Input-Gigawords", code: RADIUSAttributeTypeAcctInputGigawords},
		{name: "Acct-Output-Gigawords", code: RADIUSAttributeTypeAcctOutputGigawords},
		{name: "Event-Timestamp", code: RADIUSAttributeTypeEventTimestamp},
		{name: "CHAP-Challenge", code: RADIUSAttributeTypeCHAPChallenge},
		{name: "NAS-Port-Type", code: RADIUSAttributeTypeNASPortType},
		{name: "Port-Limit", code: RADIUSAttributeTypePortLimit},
		{name: "Login-LAT-Port", code: RADIUSAttributeTypeLoginLATPort},
		{name: "Tunnel-Type", code: RADIUSAttributeTypeTunnelType},
		{name: "Tunnel-Medium-Type", code: RADIUSAttributeTypeTunnelMediumType},
		{name: "Tunnel-Client-Endpoint", code: RADIUSAttributeTypeTunnelClientEndpoint},
		{name: "Tunnel-Server-Endpoint", code: RADIUSAttributeTypeTunnelServerEndpoint},
		{name: "Acct-Tunnel-Connection", code: RADIUSAttributeTypeAcctTunnelConnection},
		{name: "Tunnel-Password", code: RADIUSAttributeTypeTunnelPassword},
		{name: "ARAP-Password", code: RADIUSAttributeTypeARAPPassword},
		{name: "ARAP-Features", code: RADIUSAttributeTypeARAPFeatures},
		{name: "ARAP-Zone-Access", code: RADIUSAttributeTypeARAPZoneAccess},
		{name: "ARAP-Security", code: RADIUSAttributeTypeARAPSecurity},
		{name: "ARAP-Security-Data", code: RADIUSAttributeTypeARAPSecurityData},
		{name: "Password-Retry", code: RADIUSAttributeTypePasswordRetry},
		{name: "Prompt", code: RADIUSAttributeTypePrompt},
		{name: "Connect-Info", code: RADIUSAttributeTypeConnectInfo},
		{name: "Configuration-Token", code: RADIUSAttributeTypeConfigurationToken},
		{name: "EAP-Message", code: RADIUSAttributeTypeEAPMessage},
		{name: "Message-Authenticator", code: RADIUSAttributeTypeMessageAuthenticator},
		{name: "Tunnel-Private-Group-ID", code: RADIUSAttributeTypeTunnelPrivateGroupID},
		{name: "Tunnel-Assignment-ID", code: RADIUSAttributeTypeTunnelAssignmentID},
		{name: "Tunnel-Preference", code: RADIUSAttributeTypeTunnelPreference},
		{name: "ARAP-Challenge-Response", code: RADIUSAttributeTypeARAPChallengeResponse},
		{name: "Acct-Interim-Interval", code: RADIUSAttributeTypeAcctInterimInterval},
		{name: "Acct-Tunnel-Packets-Lost", code: RADIUSAttributeTypeAcctTunnelPacketsLost},
		{name: "NAS-Port-Id", code: RADIUSAttributeTypeNASPortId},
		{name: "Framed-Pool", code: RADIUSAttributeTypeFramedPool},
		{name: "Tunnel-Client-Auth-ID", code: RADIUSAttributeTypeTunnelClientAuthID},
		{name: "Tunnel-Server-Auth-ID", code: RADIUSAttributeTypeTunnelServerAuthID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name != tt.code.String() {
				t.Errorf("Failed to convert constrant value to string: %d\n", tt.code)
			}
		})
	}
}

func TestRADIUSRecordSize(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{name: "Minimum-1", size: radiusMinimumRecordSizeInBytes - 1},
		{name: "Maximum+1", size: radiusMaximumRecordSizeInBytes + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testPacketRADIUS = make([]byte, tt.size)
			p := gopacket.NewPacket(testPacketRADIUS, LayerTypeRADIUS, gopacket.Default)
			if p.ErrorLayer() == nil {
				t.Errorf("No Error layer type found in packet in %s.\n", tt.name)
			}
		})
	}
}

func TestRADIUSLengthField(t *testing.T) {
	tests := []struct {
		name string
		data *RADIUS
	}{
		{
			name: "Minimum-1",
			data: &RADIUS{
				Length: RADIUSLength(radiusMinimumRecordSizeInBytes - 1),
			},
		},
		{
			name: "Minimum+1",
			data: &RADIUS{
				Length: RADIUSLength(radiusMinimumRecordSizeInBytes + 1),
			},
		},
		{
			name: "Maximum-1",
			data: &RADIUS{
				Length: RADIUSLength(radiusMaximumRecordSizeInBytes - 1),
			},
		},
		{
			name: "Maximum+1",
			data: &RADIUS{
				Length: RADIUSLength(radiusMaximumRecordSizeInBytes + 1),
			},
		},
	}
	for _, tt := range tests {
		faliedRADIUS(t, tt.name, tt.data)
	}
}

func TestRADIUSAttributesLengthField(t *testing.T) {
	tests := []struct {
		name string
		data *RADIUS
	}{
		{
			name: "Minimum-1",
			data: &RADIUS{
				Length: RADIUSLength(radiusMinimumRecordSizeInBytes + radiusAttributesMinimumRecordSizeInBytes),
				Attributes: []RADIUSAttribute{
					{
						Length: RADIUSAttributeLength(radiusAttributesMinimumRecordSizeInBytes - 1),
						Value:  make([]byte, 1),
					},
				},
			},
		},
		{
			name: "Minimum-1",
			data: &RADIUS{
				Length: RADIUSLength(radiusMinimumRecordSizeInBytes + radiusAttributesMinimumRecordSizeInBytes - 1),
				Attributes: []RADIUSAttribute{
					{
						Length: RADIUSAttributeLength(radiusAttributesMinimumRecordSizeInBytes),
						Value:  make([]byte, 1),
					},
				},
			},
		},
		{
			name: "Minimum+1",
			data: &RADIUS{
				Length: RADIUSLength(radiusMinimumRecordSizeInBytes + radiusAttributesMinimumRecordSizeInBytes),
				Attributes: []RADIUSAttribute{
					{
						Length: RADIUSAttributeLength(radiusAttributesMinimumRecordSizeInBytes + 1),
						Value:  make([]byte, 1),
					},
				},
			},
		},
		{
			name: "Minimum+1",
			data: &RADIUS{
				Length: RADIUSLength(radiusMinimumRecordSizeInBytes + radiusAttributesMinimumRecordSizeInBytes + 1),
				Attributes: []RADIUSAttribute{
					{
						Length: RADIUSAttributeLength(radiusAttributesMinimumRecordSizeInBytes),
						Value:  make([]byte, 1),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		faliedRADIUS(t, tt.name, tt.data)
	}
}

func TestRADIUSAccessRequest(t *testing.T) {
	// This test packet is the first RADIUS packet in the RADIUS sample capture
	// pcap file radtest.pcap on the Wireshark sample captures page:
	//
	//    https://github.com/egxp/docker-compose-test-radius
	var testPacketRADIUS = []byte{
		0x02, 0x42, 0xac, 0x14, 0x00, 0x02, 0x02, 0x42, 0x06, 0x4d, 0xad, 0xbf, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x67, 0xee, 0xea, 0x40, 0x00, 0x40, 0x11, 0xf3, 0x6f, 0xac, 0x14, 0x00, 0x01, 0xac, 0x14,
		0x00, 0x02, 0xd8, 0x29, 0x07, 0x14, 0x00, 0x53, 0x58, 0x90, 0x01, 0x8d, 0x00, 0x4b, 0x3b, 0xbd,
		0x22, 0x52, 0xb4, 0xc8, 0xd8, 0x44, 0x1b, 0x46, 0x79, 0xbf, 0x4a, 0x2b, 0x86, 0x01, 0x01, 0x07,
		0x41, 0x64, 0x6d, 0x69, 0x6e, 0x02, 0x12, 0x4d, 0x2f, 0x62, 0x0b, 0x33, 0x9d, 0x6d, 0x1f, 0xe0,
		0xe4, 0x6d, 0x1f, 0x9b, 0xda, 0xff, 0xf0, 0x04, 0x06, 0x7f, 0x00, 0x01, 0x01, 0x05, 0x06, 0x00,
		0x00, 0x00, 0x00, 0x50, 0x12, 0x41, 0x73, 0xed, 0x26, 0xd3, 0xb3, 0xa9, 0x64, 0xff, 0x4d, 0xc3,
		0x0d, 0x94, 0x33, 0xe8, 0x2a,
	}

	// Assemble the RADIUS object that we expect to emerge from this test.
	pExpectedRADIUS := &RADIUS{
		BaseLayer: BaseLayer{
			Contents: []byte{
				0x01, 0x8d, 0x00, 0x4b, 0x3b, 0xbd, 0x22, 0x52, 0xb4, 0xc8, 0xd8, 0x44, 0x1b, 0x46, 0x79, 0xbf,
				0x4a, 0x2b, 0x86, 0x01, 0x01, 0x07, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x02, 0x12, 0x4d, 0x2f, 0x62,
				0x0b, 0x33, 0x9d, 0x6d, 0x1f, 0xe0, 0xe4, 0x6d, 0x1f, 0x9b, 0xda, 0xff, 0xf0, 0x04, 0x06, 0x7f,
				0x00, 0x01, 0x01, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x50, 0x12, 0x41, 0x73, 0xed, 0x26, 0xd3,
				0xb3, 0xa9, 0x64, 0xff, 0x4d, 0xc3, 0x0d, 0x94, 0x33, 0xe8, 0x2a,
			},
			Payload: nil,
		},
		Code:       RADIUSCodeAccessRequest,
		Identifier: RADIUSIdentifier(0x8d),
		Length:     RADIUSLength(0x004b),
		Authenticator: RADIUSAuthenticator([16]byte{
			0x3b, 0xbd, 0x22, 0x52, 0xb4, 0xc8, 0xd8, 0x44, 0x1b, 0x46, 0x79, 0xbf, 0x4a, 0x2b, 0x86, 0x01,
		}),
		Attributes: []RADIUSAttribute{
			{
				Type:   RADIUSAttributeTypeUserName,
				Length: RADIUSAttributeLength(0x07),
				Value:  RADIUSAttributeValue("Admin"),
			},
			{
				Type:   RADIUSAttributeTypeUserPassword,
				Length: RADIUSAttributeLength(0x12),
				Value:  RADIUSAttributeValue("\x4d\x2f\x62\x0b\x33\x9d\x6d\x1f\xe0\xe4\x6d\x1f\x9b\xda\xff\xf0"),
			},
			{
				Type:   RADIUSAttributeTypeNASIPAddress,
				Length: RADIUSAttributeLength(0x06),
				Value:  RADIUSAttributeValue("\x7f\x00\x01\x01"),
			},
			{
				Type:   RADIUSAttributeTypeNASPort,
				Length: RADIUSAttributeLength(0x06),
				Value:  RADIUSAttributeValue("\x00\x00\x00\x00"),
			},
			{
				Type:   RADIUSAttributeTypeMessageAuthenticator,
				Length: RADIUSAttributeLength(0x12),
				Value:  RADIUSAttributeValue("\x41\x73\xed\x26\xd3\xb3\xa9\x64\xff\x4d\xc3\x0d\x94\x33\xe8\x2a"),
			},
		},
	}

	checkRADIUS("AccessRequest", t, testPacketRADIUS, pExpectedRADIUS)
}

func TestRADIUSAccessAccept(t *testing.T) {
	// This test packet is the first RADIUS packet in the RADIUS sample capture
	// pcap file radtest.pcap on the Wireshark sample captures page:
	//
	//    https://github.com/egxp/docker-compose-test-radius
	var testPacketRADIUS = []byte{
		0x02, 0x42, 0x06, 0x4d, 0xad, 0xbf, 0x02, 0x42, 0xac, 0x14, 0x00, 0x02, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x30, 0xee, 0xfd, 0x00, 0x00, 0x40, 0x11, 0x33, 0x94, 0xac, 0x14, 0x00, 0x02, 0xac, 0x14,
		0x00, 0x01, 0x07, 0x14, 0xd8, 0x29, 0x00, 0x1c, 0x58, 0x59, 0x02, 0x8d, 0x00, 0x14, 0x86, 0xa8,
		0xd5, 0xcd, 0x69, 0x3c, 0x07, 0x5e, 0x9e, 0x18, 0xa2, 0x2d, 0xdd, 0x5f, 0x2b, 0xff,
	}

	// Assemble the RADIUS object that we expect to emerge from this test.
	pExpectedRADIUS := &RADIUS{
		BaseLayer: BaseLayer{
			Contents: []byte{
				0x02, 0x8d, 0x00, 0x14, 0x86, 0xa8, 0xd5, 0xcd, 0x69, 0x3c, 0x07, 0x5e, 0x9e, 0x18, 0xa2, 0x2d,
				0xdd, 0x5f, 0x2b, 0xff,
			},
			Payload: nil,
		},
		Code:       RADIUSCodeAccessAccept,
		Identifier: RADIUSIdentifier(0x8d),
		Length:     RADIUSLength(0x0014),
		Authenticator: RADIUSAuthenticator([16]byte{
			0x86, 0xa8, 0xd5, 0xcd, 0x69, 0x3c, 0x07, 0x5e, 0x9e, 0x18, 0xa2, 0x2d, 0xdd, 0x5f, 0x2b, 0xff,
		}),
	}

	checkRADIUS("AccessAccept", t, testPacketRADIUS, pExpectedRADIUS)
}
