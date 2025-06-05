package pcap

import (
	"testing"

	"github.com/NozomiNetworks/go-logger"
)

func TestLoadAndFreeNpcap(t *testing.T) {
	err := LoadNPCAP(&logger.Discard{})
	if err != nil {
		t.Fatal("load should not give error")
	}
	err = FreeNpcap()
	if err != nil {
		t.Fatal("failed to free npcap")
	}
	loaded := IsNpcapLoaded()
	if loaded {
		t.Fatal("npcap should not be loaded after free")
	}
	err = LoadNPCAP(&logger.Discard{})
	if err != nil {
		t.Fatal("failed to realod npcap")
	}
	loaded = IsNpcapLoaded()
	if !loaded {
		t.Fatal("npcap must be loaded")
	}
}
