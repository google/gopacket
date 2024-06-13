package pcap

import (
	"testing"
)

func TestNpcapHasValidSignature(t *testing.T) {
	if hasDllAValidSignature("testdata/wpcap_npcap.dll") != nil {
		t.Fail()
	}
}
