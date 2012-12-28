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

// String returns a human-readable string for the base layer.
func (b *baseLayer) String() string { return hex.Dump(b.contents) }
