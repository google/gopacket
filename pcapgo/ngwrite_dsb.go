// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
// author: CFC4N <cfc4n@cnxct.com>

package pcapgo

import (
	"encoding/binary"
)

/*
	Decryption Secrets Block (DSB) memory layout.
	via https://github.com/pcapng/pcapng/blob/master/draft-tuexen-opsawg-pcapng.md
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0 |                   Block Type = 0x0000000A                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                          Secrets Type                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                         Secrets Length                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 /                                                               /
   /                          Secrets Data                         /
   /              (variable length, padded to 32 bits)             /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                                                               /
   /                       Options (variable)                      /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                       Block Total Length                      /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	Block Type: The block type of the Decryption Secrets Block is 10.

	Block Total Length: total size of this block, as described in {{section_block}}.

	Secrets Type (32 bits): an unsigned integer identifier that describes the format of the following Secrets field. Requests for new Secrets Type codes should be made by creating a pull request to update this document as described in {{section_block_code_registry}}.

	Secrets Length (32 bits): an unsigned integer that indicates the size of the following Secrets field, without any padding octets.

	Secrets Data: binary data containing secrets, padded to a 32 bit boundary.

	Options: optionally, a list of options (formatted according to the rules defined in {{section_opt}}) can be present. No DSB-specific options are currently defined.
*/

const (
	PcapngBlockHeadersize            = 8 // block type + block total length
	PcapngDecryptionSecretsBlockSize = 8 // Secrets type + Secrets length
)

// pcapngBlockHeader is the header of a pcapng block.
type pcapngBlockHeader struct {
	blockType        uint32
	blockTotalLength uint32
}

// pcapngDecryptionSecretsBlock is the header of a section.
type pcapngDecryptionSecretsBlock struct {
	secretsType   uint32
	secretsLength uint32
}

// WriteDecryptionSecretsBlock writes a Decryption Secrets Block to the writer.
func (w *NgWriter) WriteDecryptionSecretsBlock(secretType uint32, secretPayload []byte) error {

	switch secretType {
	case DSB_SECRETS_TYPE_SSH, DSB_SECRETS_TYPE_ZIGBEE_NWK_KEY, DSB_SECRETS_TYPE_WIREGUARD, DSB_SECRETS_TYPE_ZIGBEE_APS_KEY:
		// unsupported secrets type
		return ErrUnsupportedSecretsType
	case DSB_SECRETS_TYPE_TLS:
	default:
		// unknown secrets type
		return ErrUnknownSecretsType
	}

	secretPayloadLen := len(secretPayload)
	padding := (4 - secretPayloadLen&3) & 3

	// via https://github.com/wireshark/wireshark/blob/885d6b7f731760f4a76e0f257af57d03934986ed/wiretap/pcapng.c#L5233
	// langth = MIN_DSB_SIZE + secretPayloadLen + padding
	// MIN_DSB_SIZE = MIN_BLOCK_SIZE + PcapngDecryptionSecretsBlockSize
	// MIN_BLOCK_SIZE = PcapngBlockHeadersize + 4
	//
	length := uint32(PcapngBlockHeadersize + 4 + PcapngDecryptionSecretsBlockSize + secretPayloadLen + padding)

	// write block header
	binary.LittleEndian.PutUint32(w.buf[:4], uint32(ngBlockTypeDecryptionSecrets))
	binary.LittleEndian.PutUint32(w.buf[4:8], length)

	// write decryption secrets block
	binary.LittleEndian.PutUint32(w.buf[8:12], DSB_SECRETS_TYPE_TLS)
	binary.LittleEndian.PutUint32(w.buf[12:16], uint32(secretPayloadLen))

	if _, err := w.w.Write(w.buf[:16]); err != nil {
		return err
	}

	// write secrets data
	if _, err := w.w.Write(secretPayload); err != nil {
		return err
	}

	binary.LittleEndian.PutUint32(w.buf[:4], 0)
	_, err := w.w.Write(w.buf[4-padding : 8]) // padding + length
	return err
}
