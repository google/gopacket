// Copyright 2020 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// +build gofuzz

package layers

import (
	"github.com/google/gopacket"
)

func FuzzEAPDecoder(in []byte) int {
	gopacket.NewPacket(in, LayerTypeEAP, gopacket.DecodeOptions{
		SkipDecodeRecovery: true,
	})
	return 0
}
