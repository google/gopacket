package layers

import (
	"github.com/google/gopacket"
	"testing"
)

// testPacketRadiotap0 is the packet:
//   09:34:34.799438 1.0 Mb/s 2412 MHz 11b -58dB signal antenna 7 Acknowledgment RA:88:1f:a1:ae:9d:cb
//      0x0000:  0000 1200 2e48 0000 1002 6c09 a000 c607  .....H....l.....
//      0x0010:  0000 d400 0000 881f a1ae 9dcb c630 4b4b  .............0KK
var testPacketRadiotap0 = []byte{
	0x00, 0x00, 0x12, 0x00, 0x2e, 0x48, 0x00, 0x00, 0x10, 0x02, 0x6c, 0x09, 0xa0, 0x00, 0xc6, 0x07,
	0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x88, 0x1f, 0xa1, 0xae, 0x9d, 0xcb, 0xc6, 0x30, 0x4b, 0x4b,
}

func TestPacketRadiotap0(t *testing.T) {
	p := gopacket.NewPacket(testPacketRadiotap0, LayerTypeRadioTap, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap, LayerTypeDot11}, t)
	rt := p.Layer(LayerTypeRadioTap).(*RadioTap)
	if rt.ChannelFrequency != 2412 || rt.DBMAntennaSignal != -58 || rt.Antenna != 7 {
		t.Error("Radiotap decode error")
	}
	if rt.Rate != 2 { // 500Kbps unit
		t.Error("Radiotap Rate decode error")
	}
}
func BenchmarkDecodePacketRadiotap0(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketRadiotap0, LayerTypeRadioTap, gopacket.NoCopy)
	}
}
