// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package pcap

import (
	"github.com/gconnell/gopacket"
)

func (h *Handle) Next() (gopacket.Packet, error) {
	data, ci, err := h.internalNext()
	if err != nil {
		return nil, err
	}
	p := gopacket.NewPacket(data, h.Decoder, h.DecodeOptions)
	*p.CaptureInfo() = ci
	return p, nil
}
