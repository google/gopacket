// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package pfring

import (
	"github.com/gconnell/gopacket"
)

func (r *Ring) Next() (gopacket.Packet, error) {
	data, ci, err := r.internalNext()
	if err != nil {
		return nil, err
	}
	p := gopacket.NewPacket(data, r.Decoder, r.DecodeOptions)
	*p.CaptureInfo() = ci
	return p, nil
}
