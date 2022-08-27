package layers

//
// This file is generated automatically. DO NOT EDIT.
// Generated on 2021-03-22 12:04:41.912148485 +0600 +06 m=+0.011386345
//
import (
	"bytes"
	"testing"
	"time"

	"github.com/google/gopacket"
)

// GTPv12 represents GTP session.
var GTPv12 = []struct {
	Data []byte
	gopacket.CaptureInfo
}{
	// Frame 1: 123 bytes on wire (984 bits), 123 bytes captured (984 bits)
	// Ethernet II, Src: Vendor1 (11:11:11:11:11:11), Dst: Vendor 2 (22:22:22:22:22:22)
	// 802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 601
	// Internet Protocol Version 4, Src: 100.64.187.3, Dst: 100.64.189.1
	//     0100 .... = Version: 4
	//     .... 0101 = Header Length: 20 bytes (5)
	//     Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)
	//     Total Length: 105
	//     Identification: 0xabaa (43946)
	//     Flags: 0x0000
	//     ...0 0000 0000 0000 = Fragment offset: 0
	//     Time to live: 254
	//     Protocol: UDP (17)
	//     Header checksum: 0x3a4e [validation disabled]
	//     [Header checksum status: Unverified]
	//     Source: 100.64.187.3
	//     Destination: 100.64.189.1
	// User Datagram Protocol, Src Port: 2123, Dst Port: 2123
	// GPRS Tunneling Protocol
	//     Flags: 0x32
	//     Message Type: Update PDP context response (0x13)
	//     Length: 69
	//     TEID: 0x2ccc2549 (751576393)
	//     Sequence number: 0x9bb0 (39856)
	//     Cause: Request accepted (128)
	//     Recovery: 162
	//     TEID Data I: 0x201995c0 (538547648)
	//     Charging ID: 0xd523f2a9 (3575902889)
	//     GSN address : 100.64.187.3
	//     GSN address : 100.64.187.3
	//     Quality of Service
	//     Charging Gateway address : 10.95.1.7
	//     Private Extension : NxNetworks (1)
	{
		[]byte{
			//
			// Ethernet, off: 0, len: 14
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22,
			0x22, 0x22, 0x22, 0x22, 0x81, 0x00,
			//
			// Dot1Q, off: 14, len: 4
			0x02, 0x59, 0x08, 0x00,
			//
			// IPv4, off: 18, len: 20
			0x45, 0xC0, 0x00, 0x69, 0xAB, 0xAA, 0x00, 0x00,
			0xFE, 0x11, 0x3A, 0x4E, 0x64, 0x40, 0xBB, 0x03,
			0x64, 0x40, 0xBD, 0x01,
			//
			// UDP, off: 38, len: 8
			0x08, 0x4B, 0x08, 0x4B, 0x00, 0x55, 0x00, 0x00,
			//
			// GTP, off: 46, len: 77
			0x32, 0x13, 0x00, 0x45, 0x2C, 0xCC, 0x25, 0x49,
			0x9B, 0xB0, 0x00, 0x00, 0x01, 0x80, 0x0E, 0xA2,
			0x10, 0x20, 0x19, 0x95, 0xC0, 0x7F, 0xD5, 0x23,
			0xF2, 0xA9, 0x85, 0x00, 0x04, 0x64, 0x40, 0xBB,
			0x03, 0x85, 0x00, 0x04, 0x64, 0x40, 0xBB, 0x03,
			0x87, 0x00, 0x0F, 0x02, 0x23, 0x92, 0x1F, 0x91,
			0x96, 0xFE, 0xFE, 0x44, 0xFB, 0x01, 0x01, 0x00,
			0x5A, 0x00, 0xFB, 0x00, 0x04, 0x0A, 0x5F, 0x01,
			0x07, 0xFF, 0x00, 0x09, 0x00, 0x01, 0x49, 0x53,
			0x50, 0x2E, 0x63, 0x6F, 0x6D,
		},
		gopacket.CaptureInfo{
			// 2019-06-07T22:07:16.089019+06:00
			Timestamp:     time.Unix(1559923636, 89019000),
			CaptureLength: 123,
			Length:        123,
		},
	},

	// Frame 2: 184 bytes on wire (1472 bits), 184 bytes captured (1472 bits)
	// Ethernet II, Src: Vendor1 (11:11:11:11:11:11), Dst: Vendor 2 (22:22:22:22:22:22)
	// 802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 601
	// Internet Protocol Version 4, Src: 10.90.106.138, Dst: 100.64.65.21
	//     0100 .... = Version: 4
	//     .... 0101 = Header Length: 20 bytes (5)
	//     Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)
	//     Total Length: 166
	//     Identification: 0x7eb2 (32434)
	//     Flags: 0x0000
	//     ...0 0000 0000 0000 = Fragment offset: 0
	//     Time to live: 254
	//     Protocol: UDP (17)
	//     Header checksum: 0x3991 [validation disabled]
	//     [Header checksum status: Unverified]
	//     Source: 10.90.106.138
	//     Destination: 100.64.65.21
	// User Datagram Protocol, Src Port: 2123, Dst Port: 2123
	// GPRS Tunneling Protocol V2
	//     Flags: 0x48
	//     Message Type: Create Session Response (33)
	//     Message Length: 134
	//     Tunnel Endpoint Identifier: 0x3c881f98 (1015553944)
	//     Sequence Number: 0x004c50f4 (5001460)
	//     Spare: 0
	//     Cause : Request accepted (16)
	//     Fully Qualified Tunnel Endpoint Identifier (F-TEID) : S11/S4 SGW GTP-C interface, TEID/GRE Key: 0x01c0e0f7, IPv4 10.90.106.138
	//     Fully Qualified Tunnel Endpoint Identifier (F-TEID) : S5/S8 PGW GTP-C interface, TEID/GRE Key: 0x201d95c0, IPv4 100.64.187.3
	//     APN Restriction : No Existing Contexts or Restriction (0)
	//     Aggregate Maximum Bit Rate (AMBR) :
	//     Bearer Context : [Grouped IE]
	//         IE Type: Bearer Context (93)
	//         IE Length: 63
	//         0000 .... = CR flag: 0
	//         .... 0000 = Instance: 0
	//         EPS Bearer ID (EBI) : 5
	//         Cause : Request accepted (16)
	//         Fully Qualified Tunnel Endpoint Identifier (F-TEID) : S1-U SGW GTP-U interface, TEID/GRE Key: 0x01c0e0f7, IPv4 10.106.0.152
	//         Fully Qualified Tunnel Endpoint Identifier (F-TEID) : S5/S8 PGW GTP-U interface, TEID/GRE Key: 0x201995c0, IPv4 100.64.187.3
	//         Bearer Level Quality of Service (Bearer QoS) :
	//     Recovery (Restart Counter) : 217
	//     EPS Bearer ID (EBI) : 5
	{
		[]byte{
			//
			// Ethernet, off: 0, len: 14
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22,
			0x22, 0x22, 0x22, 0x22, 0x81, 0x00,
			//
			// Dot1Q, off: 14, len: 4
			0x02, 0x59, 0x08, 0x00,
			//
			// IPv4, off: 18, len: 20
			0x45, 0xC0, 0x00, 0xA6, 0x7E, 0xB2, 0x00, 0x00,
			0xFE, 0x11, 0x39, 0x91, 0x0A, 0x5A, 0x6A, 0x8A,
			0x64, 0x40, 0x12, 0x13,
			//
			// UDP, off: 38, len: 8
			0x08, 0x4B, 0x08, 0x4B, 0x00, 0x92, 0x00, 0x00,
			//
			// GTP, off: 46, len: 138
			0x48, 0x21, 0x00, 0x86, 0x3C, 0x88, 0x1F, 0x98,
			0x4C, 0x50, 0xF4, 0x00, 0x02, 0x00, 0x02, 0x00,
			0x10, 0x00, 0x57, 0x00, 0x09, 0x00, 0x8B, 0x01,
			0xC0, 0xE0, 0xF7, 0x0A, 0x5A, 0x6A, 0x8A, 0x57,
			0x00, 0x09, 0x01, 0x87, 0x20, 0x1D, 0x95, 0xC0,
			0x64, 0x40, 0xBB, 0x03, 0x7F, 0x00, 0x01, 0x00,
			0x00, 0x48, 0x00, 0x08, 0x00, 0x00, 0x00, 0x21,
			0xC0, 0x00, 0x00, 0x7D, 0x00, 0x5D, 0x00, 0x3F,
			0x00, 0x49, 0x00, 0x01, 0x00, 0x05, 0x02, 0x00,
			0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x09, 0x00,
			0x81, 0x01, 0xC0, 0xE0, 0xF7, 0x0A, 0x6A, 0x00,
			0x98, 0x57, 0x00, 0x09, 0x02, 0x85, 0x20, 0x19,
			0x95, 0xC0, 0x64, 0x40, 0xBB, 0x03, 0x50, 0x00,
			0x16, 0x00, 0x58, 0x09, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x01, 0x00, 0xD9, 0x49, 0x00, 0x01,
			0x00, 0x05,
		},
		gopacket.CaptureInfo{
			// 2019-06-07T22:07:17.871418+06:00
			Timestamp:     time.Unix(1559923637, 871418000),
			CaptureLength: 184,
			Length:        184,
		},
	},

	// Frame 3: 94 bytes on wire (752 bits), 94 bytes captured (752 bits)
	// Ethernet II, Src: Vendor1 (11:11:11:11:11:11), Dst: Vendor 2 (22:22:22:22:22:22)
	// 802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 301
	// Internet Protocol Version 4, Src: 10.101.66.12, Dst: 10.100.1.154
	//     0100 .... = Version: 4
	//     .... 0101 = Header Length: 20 bytes (5)
	//     Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
	//     Total Length: 76
	//     Identification: 0xe118 (57624)
	//     Flags: 0x0000
	//     ...0 0000 0000 0000 = Fragment offset: 0
	//     Time to live: 253
	//     Protocol: UDP (17)
	//     Header checksum: 0x8419 [validation disabled]
	//     [Header checksum status: Unverified]
	//     Source: 10.101.66.12
	//     Destination: 10.100.1.154
	// User Datagram Protocol, Src Port: 2152, Dst Port: 2152
	// GPRS Tunneling Protocol
	//     Flags: 0x30
	//     Message Type: T-PDU (0xff)
	//     Length: 40
	//     TEID: 0x2e50ece1 (777055457)
	// Internet Protocol Version 4, Src: 10.88.70.206, Dst: 176.222.188.14
	// Transmission Control Protocol, Src Port: 54807, Dst Port: 443, Seq: 1, Ack: 2801, Len: 0
	{
		[]byte{
			//
			// Ethernet, off: 0, len: 14
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22,
			0x22, 0x22, 0x22, 0x22, 0x81, 0x00,
			//
			// Dot1Q, off: 14, len: 4
			0x01, 0x2D, 0x08, 0x00,
			//
			// IPv4, off: 18, len: 20
			0x45, 0x00, 0x00, 0x4C, 0xE1, 0x18, 0x00, 0x00,
			0xFD, 0x11, 0x84, 0x19, 0x0A, 0x65, 0x42, 0x0C,
			0x0A, 0x64, 0x01, 0x9A,
			//
			// UDP, off: 38, len: 8
			0x08, 0x68, 0x08, 0x68, 0x00, 0x38, 0x00, 0x00,
			//
			// GTPv1U, off: 46, len: 8
			0x30, 0xFF, 0x00, 0x28, 0x2E, 0x50, 0xEC, 0xE1,
			//
			// IPv4, off: 54, len: 20
			0x45, 0x00, 0x00, 0x28, 0x38, 0xED, 0x40, 0x00,
			0x3F, 0x06, 0x44, 0xD0, 0x0A, 0x58, 0x46, 0xCE,
			0xB0, 0xDE, 0xBC, 0x0E,
			//
			// TCP, off: 74, len: 20
			0xD6, 0x17, 0x01, 0xBB, 0x17, 0x2F, 0xE0, 0xE3,
			0x34, 0x29, 0x7D, 0x01, 0x50, 0x10, 0x23, 0x5E,
			0x4D, 0x53, 0x00, 0x00,
		},
		gopacket.CaptureInfo{
			// 2020-10-28T10:13:38.042403+06:00
			Timestamp:     time.Unix(1603858418, 42403000),
			CaptureLength: 94,
			Length:        94,
		},
	},
}

func assert(t testing.TB, expected bool, args ...interface{}) {
	if !expected {
		t.Helper()
		t.Fatal(args...)
	}
}

func TestGTPv1C(t *testing.T) {
	packet := gopacket.NewPacket(GTPv12[0].Data, LayerTypeEthernet, gopacket.Default)
	assert(t, packet != nil)

	pktLayers := packet.Layers()

	assert(t, len(pktLayers) == 5, len(pktLayers))

	assert(t, pktLayers[0].LayerType() == LayerTypeEthernet)
	assert(t, pktLayers[1].LayerType() == LayerTypeDot1Q)
	assert(t, pktLayers[2].LayerType() == LayerTypeIPv4)
	assert(t, pktLayers[3].LayerType() == LayerTypeUDP)
	assert(t, pktLayers[4].LayerType() == LayerTypeGTP)

	gtp, ok := pktLayers[4].(*GTP)
	assert(t, ok)

	assert(t, gtp.Version == 1)
	assert(t, gtp.V1.ProtocolType == 1)
	assert(t, gtp.V1.IsExtensionHeader == false)
	assert(t, gtp.V1.IsSequenceNumber == true)
	assert(t, gtp.V1.IsNPDU == false)
	assert(t, len(gtp.V1.ExtensionHeaders) == 0)
	assert(t, gtp.TEID == 0x2ccc2549)
	assert(t, gtp.SequenceNumber == 0x00009bb0)

	assert(t, len(gtp.Contents) == 77)
	//assert(t, len(gtp.InformationElements) == 65)
	assert(t, len(gtp.Payload) == 0)

	// parse IE
	iesDescs := []GTPInformationElement{
		{Type: 0x01, Content: []byte{
			0x80}},
		{Type: 0x0e, Content: []byte{
			0xa2}},
		{Type: 0x10, Content: []byte{
			0x20, 0x19, 0x95, 0xc0}},
		{Type: 0x7f, Content: []byte{
			0xd5, 0x23, 0xf2, 0xa9}},
		{Type: 0x85, Content: []byte{
			0x64, 0x40, 0xbb, 0x03}},
		{Type: 0x85, Content: []byte{
			0x64, 0x40, 0xbb, 0x03}},
		{Type: 0x87, Content: []byte{
			0x02, 0x23, 0x92, 0x1f, 0x91, 0x96, 0xfe, 0xfe,
			0x44, 0xfb, 0x01, 0x01, 0x00, 0x5a, 0x00}},
		{Type: 0xfb, Content: []byte{
			0x0a, 0x5f, 0x01, 0x07}},
		{Type: 0xff, Content: []byte{
			0x00, 0x01, 0x49, 0x53, 0x50, 0x2e, 0x63, 0x6f,
			0x6d}},
	}

	ies := gtp.InformationElements
	assert(t, len(ies) == len(iesDescs), len(ies))
	for i := range iesDescs {
		assert(t, iesDescs[i].Type == ies[i].Type, i)
		assert(t, bytes.Equal(iesDescs[i].Content, ies[i].Content), i)
	}
}

func TestGTPv2C(t *testing.T) {
	packet := gopacket.NewPacket(GTPv12[1].Data, LayerTypeEthernet, gopacket.Default)
	assert(t, packet != nil)

	pktLayers := packet.Layers()

	assert(t, len(pktLayers) == 5, len(pktLayers))

	assert(t, pktLayers[0].LayerType() == LayerTypeEthernet)
	assert(t, pktLayers[1].LayerType() == LayerTypeDot1Q)
	assert(t, pktLayers[2].LayerType() == LayerTypeIPv4)
	assert(t, pktLayers[3].LayerType() == LayerTypeUDP)
	assert(t, pktLayers[4].LayerType() == LayerTypeGTP, pktLayers[4].LayerType())

	gtp, ok := pktLayers[4].(*GTP)
	assert(t, ok)

	assert(t, gtp.Version == 2)
	assert(t, gtp.TEID == 0x3c881f98)
	assert(t, gtp.SequenceNumber == 0x004c50f4)
	assert(t, gtp.V2.IsPiggyback == false)
	assert(t, gtp.V2.IsTEID == true)
	assert(t, gtp.V2.IsMsgPrio == false)

	assert(t, len(gtp.Contents) == 138, len(gtp.Contents))
	//assert(t, len(gtp.InformationElements) == 126)
	assert(t, len(gtp.Payload) == 0)

	// parse IE
	ies := gtp.InformationElements

	iesDescs := []GTPInformationElement{
		{Type: 0x02, Instance: 0, IsGrouped: false, Content: []byte{
			0x10, 0x00}},
		{Type: 0x57, Instance: 0, IsGrouped: false, Content: []byte{
			0x8b, 0x01, 0xc0, 0xe0, 0xf7, 0x0a, 0x5a, 0x6a,
			0x8a}},
		{Type: 0x57, Instance: 1, IsGrouped: false, Content: []byte{
			0x87, 0x20, 0x1d, 0x95, 0xc0, 0x64, 0x40, 0xbb,
			0x03}},
		{Type: 0x7f, Instance: 0, IsGrouped: false, Content: []byte{
			0x00}},
		{Type: 0x48, Instance: 0, IsGrouped: false, Content: []byte{
			0x00, 0x00, 0x21, 0xc0, 0x00, 0x00, 0x7d, 0x00}},
		{Type: 0x5d, Instance: 0, IsGrouped: true, Content: []byte{
			0x49, 0x00, 0x01, 0x00, 0x05, 0x02, 0x00, 0x02,
			0x00, 0x10, 0x00, 0x57, 0x00, 0x09, 0x00, 0x81,
			0x01, 0xc0, 0xe0, 0xf7, 0x0a, 0x6a, 0x00, 0x98,
			0x57, 0x00, 0x09, 0x02, 0x85, 0x20, 0x19, 0x95,
			0xc0, 0x64, 0x40, 0xbb, 0x03, 0x50, 0x00, 0x16,
			0x00, 0x58, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{Type: 0x03, Instance: 0, IsGrouped: false, Content: []byte{
			0xd9}},
		{Type: 0x49, Instance: 0, IsGrouped: false, Content: []byte{
			0x05}},
	}

	assert(t, len(ies) == len(iesDescs), len(ies))

	for i := range iesDescs {
		assert(t, iesDescs[i].Type == ies[i].Type, i)
		assert(t, iesDescs[i].Instance == ies[i].Instance, i)
		assert(t, iesDescs[i].IsGrouped == ies[i].IsGrouped, i)
		assert(t, bytes.Equal(iesDescs[i].Content, ies[i].Content), i)
	}

	// parse Bearer Context
	assert(t, ies[5].IsGrouped)
	ies = ies[5].InformationElements

	iesDescs = []GTPInformationElement{
		{Type: 0x49, Instance: 0, IsGrouped: false, Content: []byte{
			0x05}},
		{Type: 0x02, Instance: 0, IsGrouped: false, Content: []byte{
			0x10, 0x00}},
		{Type: 0x57, Instance: 0, IsGrouped: false, Content: []byte{
			0x81, 0x01, 0xc0, 0xe0, 0xf7, 0x0a, 0x6a, 0x00,
			0x98}},
		{Type: 0x57, Instance: 2, IsGrouped: false, Content: []byte{
			0x85, 0x20, 0x19, 0x95, 0xc0, 0x64, 0x40, 0xbb,
			0x03}},
		{Type: 0x50, Instance: 0, IsGrouped: false, Content: []byte{
			0x58, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	assert(t, len(ies) == len(iesDescs), len(ies))

	for i := range iesDescs {
		assert(t, iesDescs[i].Type == ies[i].Type, i)
		assert(t, iesDescs[i].Instance == ies[i].Instance, i)
		assert(t, iesDescs[i].IsGrouped == ies[i].IsGrouped, i)
		assert(t, bytes.Equal(iesDescs[i].Content, ies[i].Content), i)
	}
}

func TestGTPv1U_WithGTP(t *testing.T) {
	RegisterUDPPortLayerType(UDPPort(2152), LayerTypeGTP)
	defer RegisterUDPPortLayerType(UDPPort(2152), LayerTypeGTPv1U)

	packet := gopacket.NewPacket(GTPv12[2].Data, LayerTypeEthernet, gopacket.Default)
	assert(t, packet != nil)

	pktLayers := packet.Layers()

	assert(t, len(pktLayers) == 7, len(pktLayers))

	assert(t, pktLayers[0].LayerType() == LayerTypeEthernet)
	assert(t, pktLayers[1].LayerType() == LayerTypeDot1Q)
	assert(t, pktLayers[2].LayerType() == LayerTypeIPv4)
	assert(t, pktLayers[3].LayerType() == LayerTypeUDP)
	assert(t, pktLayers[4].LayerType() == LayerTypeGTP)
	assert(t, pktLayers[5].LayerType() == LayerTypeIPv4)
	assert(t, pktLayers[6].LayerType() == LayerTypeTCP)

	gtp, ok := pktLayers[4].(*GTP)
	assert(t, ok)

	assert(t, gtp.Version == 1)
	assert(t, gtp.Type == 0xff)
	assert(t, gtp.TEID == 0x2e50ece1, gtp.TEID)
	assert(t, gtp.V1.IsExtensionHeader == false)
	assert(t, gtp.V1.IsNPDU == false)
	assert(t, gtp.V1.IsSequenceNumber == false)
}

func BenchmarkGTPv2(b *testing.B) {
	packet := gopacket.NewPacket(GTPv12[1].Data, LayerTypeEthernet, gopacket.Default)

	pktLayers := packet.Layers()

	assert(b, pktLayers[0].LayerType() == LayerTypeEthernet)
	assert(b, pktLayers[1].LayerType() == LayerTypeDot1Q)
	assert(b, pktLayers[2].LayerType() == LayerTypeIPv4)
	assert(b, pktLayers[3].LayerType() == LayerTypeUDP)
	assert(b, pktLayers[4].LayerType() == LayerTypeGTP, pktLayers[4].LayerType())

	gtp, ok := pktLayers[4].(*GTP)
	assert(b, ok)
	assert(b, gtp.Version == 2)

	assert(b, len(gtp.Contents) == 138, len(gtp.Contents))
	assert(b, len(gtp.Payload) == 0)

	data := gtp.Contents
	gtp = &GTP{}

	err := gtp.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	assert(b, err == nil)

	for i := 0; i < b.N; i++ {
		err = gtp.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	}

	assert(b, err == nil)
}

func BenchmarkGTPv1U_WithGTP(b *testing.B) {
	RegisterUDPPortLayerType(UDPPort(2152), LayerTypeGTP)
	defer RegisterUDPPortLayerType(UDPPort(2152), LayerTypeGTPv1U)

	packet := gopacket.NewPacket(GTPv12[2].Data, LayerTypeEthernet, gopacket.Default)
	assert(b, packet != nil)

	pktLayers := packet.Layers()

	assert(b, len(pktLayers) == 7, len(pktLayers))

	assert(b, pktLayers[0].LayerType() == LayerTypeEthernet)
	assert(b, pktLayers[1].LayerType() == LayerTypeDot1Q)
	assert(b, pktLayers[2].LayerType() == LayerTypeIPv4)
	assert(b, pktLayers[3].LayerType() == LayerTypeUDP)
	assert(b, pktLayers[4].LayerType() == LayerTypeGTP)
	assert(b, pktLayers[5].LayerType() == LayerTypeIPv4)
	assert(b, pktLayers[6].LayerType() == LayerTypeTCP)

	gtp, ok := pktLayers[4].(*GTP)
	assert(b, ok)

	assert(b, gtp.Version == 1)
	assert(b, gtp.Type == 0xff)
	assert(b, gtp.TEID == 0x2e50ece1, gtp.TEID)
	assert(b, gtp.V1.IsExtensionHeader == false)
	assert(b, gtp.V1.IsNPDU == false)
	assert(b, gtp.V1.IsSequenceNumber == false)

	gtpData := append(gtp.Contents, gtp.Payload...)
	err := gtp.DecodeFromBytes(gtpData, gopacket.NilDecodeFeedback)
	assert(b, err == nil, err)
	for i := 0; i < b.N; i++ {
		gtp.DecodeFromBytes(gtpData, gopacket.NilDecodeFeedback)
	}
}

func BenchmarkGTPv1U(b *testing.B) {
	RegisterUDPPortLayerType(UDPPort(2152), LayerTypeGTP)
	defer RegisterUDPPortLayerType(UDPPort(2152), LayerTypeGTPv1U)

	packet := gopacket.NewPacket(GTPv12[2].Data, LayerTypeEthernet, gopacket.Default)
	assert(b, packet != nil)

	pktLayers := packet.Layers()

	assert(b, len(pktLayers) == 7, len(pktLayers))

	assert(b, pktLayers[0].LayerType() == LayerTypeEthernet)
	assert(b, pktLayers[1].LayerType() == LayerTypeDot1Q)
	assert(b, pktLayers[2].LayerType() == LayerTypeIPv4)
	assert(b, pktLayers[3].LayerType() == LayerTypeUDP)
	assert(b, pktLayers[4].LayerType() == LayerTypeGTP)
	assert(b, pktLayers[5].LayerType() == LayerTypeIPv4)
	assert(b, pktLayers[6].LayerType() == LayerTypeTCP)

	gtp, ok := pktLayers[4].(*GTP)
	assert(b, ok)

	assert(b, gtp.Version == 1)
	assert(b, gtp.Type == 0xff)
	assert(b, gtp.TEID == 0x2e50ece1, gtp.TEID)
	assert(b, gtp.V1.IsExtensionHeader == false)
	assert(b, gtp.V1.IsNPDU == false)
	assert(b, gtp.V1.IsSequenceNumber == false)

	gtpv1u := new(GTPv1U)

	gtpData := append(gtp.Contents, gtp.Payload...)
	err := gtpv1u.DecodeFromBytes(gtpData, gopacket.NilDecodeFeedback)
	assert(b, err == nil, err)

	for i := 0; i < b.N; i++ {
		gtpv1u.DecodeFromBytes(gtpData, gopacket.NilDecodeFeedback)
	}
}
