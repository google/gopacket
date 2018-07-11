// Copyright 2018 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
package layers

import (
	"reflect"
	"testing"

	"github.com/google/gopacket"
)

func TestDecodeAndEncode(t *testing.T) {
	erspan := &ERSPANIIHeader{
		Version:        ERSPANIIVersion,
		VLANIdentifier: 0x2aa,
		CoS:            0x4,
		TrunkEncap:     0x2,
		IsTruncated:    true,
		SessionID:      0x2aa,
		Reserved:       0x155,
		Index:          0xF0F0F,
	}
	expectedBytes := []byte{0x12, 0xaa, 0x96, 0xaa, 0x15, 0x5F, 0x0F, 0x0F}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	erspan.SerializeTo(buf, opts)

	if !reflect.DeepEqual(buf.Bytes(), expectedBytes) {
		t.Fatalf("Got %+v, expected %+v\n", buf.Bytes(), expectedBytes)
	}

	erspan2 := &ERSPANIIHeader{}
	erspan2.DecodeFromBytes(buf.Bytes(), gopacket.NilDecodeFeedback)
	if !reflect.DeepEqual(*erspan, *erspan2) {
		t.Fatalf("Got %+v, expected %+v\n", erspan2, erspan)
	}
}

func TestNewERSPAN2(t *testing.T) {
	erspan := NewERSPANIIHeader()
	if erspan.Version != ERSPANIIVersion {
		t.Fatalf("Got %v, expected %v\n", erspan.Version, ERSPANIIVersion)
	}
}
