package ip4defrag

import (
  "code.google.com/p/gopacket"
  "code.google.com/p/gopacket/layers"
)

func Fragmented(i *layers.IPv4) bool {
	return i.Flags & layers.IPv4MoreFragments != 0 || i.FragOffset > 0
}

type fragment struct {
	bytes []byte
}

type fragmentKey struct {
	flow gopacket.Flow
	id uint16
}

type Defrag struct {
	ip4 layers.IPv4
	fragments map[fragmentKey]
}
