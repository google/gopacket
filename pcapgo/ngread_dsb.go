// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
// author: CFC4N <cfc4n@cnxct.com>

package pcapgo

import "fmt"

type decryptionSecret struct {
	blockInfo pcapngDecryptionSecretsBlock
	payload   []byte
}

// readDecryptionSecrets parses an encryption secrets section from the given
func (r *NgReader) readDecryptionSecretsBlock() error {
	if err := r.readBytes(r.buf[:8]); err != nil {
		return fmt.Errorf("could not read DecryptionSecret Header block length: %v", err)
	}
	r.currentBlock.length -= 8

	var decryptionSecretsBlock = &pcapngDecryptionSecretsBlock{}
	decryptionSecretsBlock.secretsType = r.getUint32(r.buf[0:4])
	decryptionSecretsBlock.secretsLength = r.getUint32(r.buf[4:8])
	var payload = make([]byte, decryptionSecretsBlock.secretsLength)
	if err := r.readBytes(payload); err != nil {
		return fmt.Errorf("could not read %d bytes from DecryptionSecret payload: %v", decryptionSecretsBlock.secretsLength, err)
	}
	r.currentBlock.length -= uint32(len(payload))

	// save decryption secrets
	var decryptSecret decryptionSecret
	decryptSecret.blockInfo = *decryptionSecretsBlock
	decryptSecret.payload = payload
	r.decryptionSecrets = append(r.decryptionSecrets, decryptSecret)
	return nil
}
