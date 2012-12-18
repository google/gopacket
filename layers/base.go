package layers

import ()

// baseLayer is a convenience struct which implements the LayerData and
// LayerPayload functions of the Layer interface.
type baseLayer struct {
	contents, payload []byte
}

func (b *baseLayer) LayerContents() []byte { return b.contents }
func (b *baseLayer) LayerPayload() []byte  { return b.payload }
