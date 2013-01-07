package layers

// baseLayer is a convenience struct which implements the LayerData and
// LayerPayload functions of the Layer interface.
type baseLayer struct {
	contents, payload []byte
}

// LayerContents returns the bytes of the packet layer.
func (b *baseLayer) LayerContents() []byte { return b.contents }

// LayerPayload returns the bytes contained within the packet layer.
func (b *baseLayer) LayerPayload() []byte { return b.payload }
