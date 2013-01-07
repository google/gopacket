// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/hex"
)

// baseLayer is a convenience struct which implements the LayerData and
// LayerPayload functions of the Layer interface.
type baseLayer struct {
	contents, payload []byte
}

// LayerContents returns the bytes of the packet layer.
func (b *baseLayer) LayerContents() []byte { return b.contents }

// LayerPayload returns the bytes contained within the packet layer.
func (b *baseLayer) LayerPayload() []byte { return b.payload }

// String returns a human-readable string for the packet layer.
func (b *baseLayer) String() string { return hex.Dump(b.contents) }
