// Copyright 2025 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
)

func ppiHeader(version, flags uint8, length uint16, dlt uint32, payload []byte) []byte {
	h := make([]byte, ppiCommonHeaderLength, ppiCommonHeaderLength+len(payload))
	h[0] = version
	h[1] = flags
	binary.LittleEndian.PutUint16(h[2:4], length)
	binary.LittleEndian.PutUint32(h[4:8], dlt)
	return append(h, payload...)
}

func TestPPIDecodeFromBytes(t *testing.T) {
	ethPayload := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dot11Payload := []byte{0x80, 0x00, 0x00, 0x00}

	tests := []struct {
		name        string
		data        []byte
		wantErr     bool
		wantNext    gopacket.LayerType
		wantPayload []byte
	}{
		{
			name:        "ethernet dlt",
			data:        ppiHeader(0, 0, 8, uint32(LinkTypeEthernet), ethPayload),
			wantNext:    LayerTypeEthernet,
			wantPayload: ethPayload,
		},
		{
			name:        "802.11 dlt",
			data:        ppiHeader(0, 0, 8, uint32(LinkTypeIEEE802_11), dot11Payload),
			wantNext:    LayerTypeDot11,
			wantPayload: dot11Payload,
		},
		{
			name:    "truncated",
			data:    []byte{0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "version nonzero",
			data:    ppiHeader(1, 0, 8, uint32(LinkTypeEthernet), ethPayload),
			wantErr: true,
		},
		{
			name:    "length less than 8",
			data:    ppiHeader(0, 0, 4, uint32(LinkTypeEthernet), ethPayload),
			wantErr: true,
		},
		{
			name:    "length exceeds packet",
			data:    ppiHeader(0, 0, 20, uint32(LinkTypeEthernet), ethPayload),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ppi := &PPI{}
			err := ppi.DecodeFromBytes(tt.data, gopacket.NilDecodeFeedback)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("DecodeFromBytes() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeFromBytes() unexpected error: %v", err)
			}
			if got := ppi.NextLayerType(); got != tt.wantNext {
				t.Errorf("NextLayerType() = %v, want %v", got, tt.wantNext)
			}
			if !bytes.Equal(ppi.Payload, tt.wantPayload) {
				t.Errorf("Payload = %v, want %v", ppi.Payload, tt.wantPayload)
			}
		})
	}
}

func TestPPINewPacket(t *testing.T) {
	payload := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
	}
	data := ppiHeader(0, 0, 8, uint32(LinkTypeEthernet), payload)
	p := gopacket.NewPacket(data, LinkTypePPI, gopacket.Default)
	got := p.Layer(LayerTypePPI)
	if got == nil {
		t.Fatal("missing PPI layer")
	}
	ppi, ok := got.(*PPI)
	if !ok {
		t.Fatalf("Layer(LayerTypePPI) type = %T, want *PPI", got)
	}
	if ppi.NextLayerType() != LayerTypeEthernet {
		t.Errorf("NextLayerType() = %v, want %v", ppi.NextLayerType(), LayerTypeEthernet)
	}
	if !bytes.Equal(ppi.Payload, payload) {
		t.Errorf("Payload = %v, want %v", ppi.Payload, payload)
	}
}
