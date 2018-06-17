// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
// TLS decoder is a contribution from Jose Selvi
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"

	"github.com/google/gopacket"
)

type TLSappdataRecord struct {
	TLSrecordHeader
	Payload []byte
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSappdataRecord) DecodeFromBytes(h TLSrecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	if len(data) != int(t.Length) {
		return errors.New("TLS Application Data length mismatch")
	}

	t.Payload = data
	return nil
}
