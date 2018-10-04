// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"

	"github.com/google/gopacket"
)

type TLSchangeCipherSpec uint8

const (
	TLSchangecipherspec_message TLSchangeCipherSpec = 1
	TLSchangecipherspec_unknown TLSchangeCipherSpec = 255
)

//  TLS Change Cipher Spec
//  0  1  2  3  4  5  6  7  8
//  +--+--+--+--+--+--+--+--+
//  |        Message        |
//  +--+--+--+--+--+--+--+--+

type TLSchangeCipherSpecRecord struct {
	TLSrecordHeader

	Message TLSchangeCipherSpec
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSchangeCipherSpecRecord) DecodeFromBytes(h TLSrecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	if len(data) != 1 {
		df.SetTruncated()
		return errors.New("TLS Change Cipher Spec record incorrect length")
	}

	t.Message = TLSchangeCipherSpec(data[0])
	if t.Message != TLSchangecipherspec_message {
		t.Message = TLSchangecipherspec_unknown
	}

	return nil
}

func (ccs TLSchangeCipherSpec) String() string {
	switch ccs {
	default:
		return "Unknown"
	case TLSchangecipherspec_message:
		return "Change Cipher Spec Message"
	}
}
