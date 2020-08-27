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
	erspan := &ERSPANII{
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

	erspan2 := &ERSPANII{}
	erspan2.DecodeFromBytes(buf.Bytes(), gopacket.NilDecodeFeedback)
	if erspan.Version != erspan2.Version {
		t.Fatalf("Got %+v, expected %+v\n", erspan2.Version, erspan.Version)
	}
	if erspan.VLANIdentifier != erspan2.VLANIdentifier {
		t.Fatalf("Got %+v, expected %+v\n", erspan2.VLANIdentifier, erspan.VLANIdentifier)
	}
	if erspan.CoS != erspan2.CoS {
		t.Fatalf("Got %+v, expected %+v\n", erspan2.CoS, erspan.CoS)
	}
	if erspan.TrunkEncap != erspan2.TrunkEncap {
		t.Fatalf("Got %+v, expected %+v\n", erspan2.TrunkEncap, erspan.TrunkEncap)
	}
	if erspan.IsTruncated != erspan2.IsTruncated {
		t.Fatalf("Got %+v, expected %+v\n", erspan2.IsTruncated, erspan.IsTruncated)
	}
	if erspan.SessionID != erspan2.SessionID {
		t.Fatalf("Got %+v, expected %+v\n", erspan2.SessionID, erspan.SessionID)
	}
	if erspan.Reserved != erspan2.Reserved {
		t.Fatalf("Got %+v, expected %+v\n", erspan2.Reserved, erspan.Reserved)
	}
}
