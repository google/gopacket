package layers

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"

	"github.com/google/gopacket"
)

func hwAddr(t testing.TB, s string) net.HardwareAddr {
	addr, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(s, err)
	}
	return addr
}

func TestLinuxSLLDecode(t *testing.T) {
	samples := []struct {
		Packet string
		Layer  LinuxSLL
	}{
		{
			Packet: "0000000100060015c7197d0000000800",
			Layer: LinuxSLL{
				PacketType:   LinuxSLLPacketTypeHost,
				AddrLen:      6,
				Addr:         hwAddr(t, "00:15:c7:19:7d:00"),
				EthernetType: EthernetTypeIPv4,
				AddrType:     1,
			},
		},
	}

	for i := range samples {
		s := &samples[i]
		b, err := hex.DecodeString(s.Packet)
		if err != nil {
			t.Fatal(s.Packet, err)
		}

		decoded := &LinuxSLL{}
		if err := decoded.DecodeFromBytes(b, gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(s.Packet, err)
		}

		if !bytes.Equal(decoded.Contents, b) {
			t.Fatal(s.Packet)
		}

		if decoded.PacketType != s.Layer.PacketType {
			t.Fatal(s.Packet)
		}

		if decoded.AddrLen != s.Layer.AddrLen {
			t.Fatal(s.Packet)
		}

		if !bytes.Equal(decoded.Addr, s.Layer.Addr) {
			t.Fatal(s.Packet)
		}

		if decoded.EthernetType != s.Layer.EthernetType {
			t.Fatal(s.Packet)
		}

		if decoded.AddrType != s.Layer.AddrType {
			t.Fatal(s.Packet)
		}
	}
}

func TestLinuxSLLDecodeInvalid(t *testing.T) {
	samples := []struct {
		Packet string
		Layer  LinuxSLL
	}{
		{
			Packet: "00000001ffff0015c7197d0000000800",
			Layer: LinuxSLL{
				PacketType:   LinuxSLLPacketTypeHost,
				AddrLen:      0xffff,
				Addr:         hwAddr(t, "00:15:c7:19:7d:00"),
				EthernetType: EthernetTypeIPv4,
				AddrType:     1,
			},
		},
	}

	for i := range samples {
		s := &samples[i]
		b, err := hex.DecodeString(s.Packet)
		if err != nil {
			t.Fatal(s.Packet, err)
		}

		decoded := &LinuxSLL{}
		if err := decoded.DecodeFromBytes(b, gopacket.NilDecodeFeedback); err == nil {
			t.Fatal(s.Packet, "packet is invalid")
		}
	}
}
