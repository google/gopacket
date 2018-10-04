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

type TLSalertLevel uint8
type TLSalertDescr uint8

const (
	TLSalert_warning       TLSalertLevel = 1
	TLSalert_fatal         TLSalertLevel = 2
	TLSalert_unknown_level TLSalertLevel = 255

	TLSalert_close_notify                TLSalertDescr = 0
	TLSalert_unexpected_message          TLSalertDescr = 10
	TLSalert_bad_record_mac              TLSalertDescr = 20
	TLSalert_decryption_failed_RESERVED  TLSalertDescr = 21
	TLSalert_record_overflow             TLSalertDescr = 22
	TLSalert_decompression_failure       TLSalertDescr = 30
	TLSalert_handshake_failure           TLSalertDescr = 40
	TLSalert_no_certificate_RESERVED     TLSalertDescr = 41
	TLSalert_bad_certificate             TLSalertDescr = 42
	TLSalert_unsupported_certificate     TLSalertDescr = 43
	TLSalert_certificate_revoked         TLSalertDescr = 44
	TLSalert_certificate_expired         TLSalertDescr = 45
	TLSalert_certificate_unknown         TLSalertDescr = 46
	TLSalert_illegal_parameter           TLSalertDescr = 47
	TLSalert_unknown_ca                  TLSalertDescr = 48
	TLSalert_access_denied               TLSalertDescr = 49
	TLSalert_decode_error                TLSalertDescr = 50
	TLSalert_decrypt_error               TLSalertDescr = 51
	TLSalert_export_restriction_RESERVED TLSalertDescr = 60
	TLSalert_protocol_version            TLSalertDescr = 70
	TLSalert_insufficient_security       TLSalertDescr = 71
	TLSalert_internal_error              TLSalertDescr = 80
	TLSalert_user_canceled               TLSalertDescr = 90
	TLSalert_no_renegotiation            TLSalertDescr = 100
	TLSalert_unsupported_extension       TLSalertDescr = 110
	TLSalert_unknown_description         TLSalertDescr = 255
)

//  TLS Alert
//  0  1  2  3  4  5  6  7  8
//  +--+--+--+--+--+--+--+--+
//  |         Level         |
//  +--+--+--+--+--+--+--+--+
//  |      Description      |
//  +--+--+--+--+--+--+--+--+

type TLSalertRecord struct {
	TLSrecordHeader

	Level       TLSalertLevel
	Description TLSalertDescr

	EncryptedMsg []byte
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSalertRecord) DecodeFromBytes(h TLSrecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	if len(data) < 2 {
		df.SetTruncated()
		return errors.New("TLS Alert packet too short")
	}

	if t.Length == 2 {
		t.Level = TLSalertLevel(data[0])
		t.Description = TLSalertDescr(data[1])
	} else {
		t.Level = TLSalert_unknown_level
		t.Description = TLSalert_unknown_description
		t.EncryptedMsg = data
	}

	return nil
}

func (al TLSalertLevel) String() string {
	switch al {
	default:
		return "Unknown"
	case TLSalert_warning:
		return "Warning"
	case TLSalert_fatal:
		return "Fatal"
	}
}

func (ad TLSalertDescr) String() string {
	switch ad {
	default:
		return "Unknown"
	case TLSalert_close_notify:
		return "close_notify"
	case TLSalert_unexpected_message:
		return "unexpected_message"
	case TLSalert_bad_record_mac:
		return "bad_record_mac"
	case TLSalert_decryption_failed_RESERVED:
		return "decryption_failed_RESERVED"
	case TLSalert_record_overflow:
		return "record_overflow"
	case TLSalert_decompression_failure:
		return "decompression_failure"
	case TLSalert_handshake_failure:
		return "handshake_failure"
	case TLSalert_no_certificate_RESERVED:
		return "no_certificate_RESERVED"
	case TLSalert_bad_certificate:
		return "bad_certificate"
	case TLSalert_unsupported_certificate:
		return "unsupported_certificate"
	case TLSalert_certificate_revoked:
		return "certificate_revoked"
	case TLSalert_certificate_expired:
		return "certificate_expired"
	case TLSalert_certificate_unknown:
		return "certificate_unknown"
	case TLSalert_illegal_parameter:
		return "illegal_parameter"
	case TLSalert_unknown_ca:
		return "unknown_ca"
	case TLSalert_access_denied:
		return "access_denied"
	case TLSalert_decode_error:
		return "decode_error"
	case TLSalert_decrypt_error:
		return "decrypt_error"
	case TLSalert_export_restriction_RESERVED:
		return "export_restriction_RESERVED"
	case TLSalert_protocol_version:
		return "protocol_version"
	case TLSalert_insufficient_security:
		return "insufficient_security"
	case TLSalert_internal_error:
		return "internal_error"
	case TLSalert_user_canceled:
		return "user_canceled"
	case TLSalert_no_renegotiation:
		return "no_renegotiation"
	case TLSalert_unsupported_extension:
		return "unsupported_extension"
	}
}
