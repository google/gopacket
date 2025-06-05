package pcap

import (
	"testing"

	"github.com/NozomiNetworks/go-logger"
)

func TestNpcapHasValidSignature(t *testing.T) {
	if hasDllAValidSignature("testdata/wpcap_npcap.dll", &logger.Discard{}) != nil {
		t.Fail()
	}
}
