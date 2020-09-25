// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"github.com/google/gopacket"
)

// TLSHandshakeType defines the type of TLS handshake
type TLSHandshakeType uint8

// TLSHandshakeType known values.
const (
	TLSHandshakeHelloRequest       TLSHandshakeType = 0
	TLSHandshakeClientHello        TLSHandshakeType = 1
	TLSHandshakeServerHello        TLSHandshakeType = 2
	TLSHandshakeCertificate        TLSHandshakeType = 11
	TLSHandshakeServerKeyExchange  TLSHandshakeType = 12
	TLSHandshakeCertificateRequest TLSHandshakeType = 13
	TLSHandshakeServerDone         TLSHandshakeType = 14
	TLSHandshakeCertificateVerify  TLSHandshakeType = 15
	TLSHandshakeClientKeyExchange  TLSHandshakeType = 16
	TLSHandshakeFinished           TLSHandshakeType = 20
)

var validHandshakeValues = map[TLSHandshakeType]bool{
	TLSHandshakeHelloRequest:       true,
	TLSHandshakeClientHello:        true,
	TLSHandshakeServerHello:        true,
	TLSHandshakeCertificate:        true,
	TLSHandshakeServerKeyExchange:  true,
	TLSHandshakeCertificateRequest: true,
	TLSHandshakeServerDone:         true,
	TLSHandshakeCertificateVerify:  true,
	TLSHandshakeClientKeyExchange:  true,
	TLSHandshakeFinished:           true,
}

// TLSHandshakeRecord defines the structure of a Handshare Record
type TLSHandshakeRecord struct {
	TLSRecordHeader
	// HandshakeType represents type of handshake. Note this is nil when handshake type is unknown due to encryption
	HandshakeType *TLSHandshakeType
	Record        []byte
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, encrypted bool, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length
	t.Record = data

	encrypted = encrypted || isEncrypted(data)
	if encrypted {
		return nil
	}

	handshakeType := TLSHandshakeType(data[0])
	t.HandshakeType = &handshakeType

	return nil
}

// isEncrypted checks if packet seems encrypted (heuristics)
func isEncrypted(data []byte) bool {
	// heuristics used by wireshark
	// https://github.com/wireshark/wireshark/blob/d5fe2d494c6475263b954a36812b888b11e1a50b/epan/dissectors/packet-tls.c#L2158a
	if len(data) < 16 {
		return false
	}
	if len(data) > 0x010000 {
		return true
	}

	_, ok := validHandshakeValues[TLSHandshakeType(data[0])]
	return !ok
}
