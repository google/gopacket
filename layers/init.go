package layers

import "github.com/google/gopacket"

func init() {
	// avoid initialization loop
	LayerTypeGTP = gopacket.RegisterLayerType(147, gopacket.LayerTypeMetadata{Name: "GTP", Decoder: gopacket.DecodeFunc(decodeGTP)})
}
