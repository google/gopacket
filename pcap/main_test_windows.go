package pcap

import (
	"testing"

	"github.com/NozomiNetworks/go-logger"
)

func TestMain(m *testing.M) {
	_ = LoadNPCAP(&logger.Discard{})
}
