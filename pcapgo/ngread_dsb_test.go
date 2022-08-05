package pcapgo

import (
	"fmt"
	"github.com/google/gopacket"
	"io"
	"os"
	"testing"
	"time"
)

type BufferPacketSource struct {
	index int
	data  [][]byte
	ci    []gopacket.CaptureInfo
}

// TestNgReadDSB tests the readDecryptionSecretsBlock function.
func TestNgReaderDSB(t *testing.T) {

	// Test that we can read a pcapng file with DSB.
	pcapngFile := "tests/le/test301.pcapng"
	start := time.Now()
	testf, err := os.Open(pcapngFile)
	if err != nil {
		t.Fatal("Couldn't open file:", err)
	}
	defer testf.Close()
	options := DefaultNgReaderOptions
	options.SkipUnknownVersion = true

	var r *NgReader
	r, err = NewNgReader(testf, options)
	if err != nil {
		t.Fatal("Couldn't read start of file:", err)
	}

	b := &BufferPacketSource{}
	var ii int
	var found bool
	for {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			t.Log("ReadPacketData returned EOF")
			break
		}
		b.data = append(b.data, data)
		b.ci = append(b.ci, ci)
		if !found && len(r.decryptionSecrets) > 0 {
			found = true
			t.Log("Decryption Secrets Block found, index block:", ii)
		}
		ii++
	}
	if len(b.data) != len(b.ci) || len(b.ci) <= 0 {
		t.Fatal("unexpected data or data length:", len(b.data), ", ci length", len(b.ci))
	}

	duration := time.Since(start)
	t.Logf("bigEndian %t", r.bigEndian)
	t.Logf("Reading packet data into memory: %d packets in %v, %v per packet\n", len(b.data), duration, duration/time.Duration(len(b.data)))

	t.Log("decryptionSecrets:", len(r.decryptionSecrets))
	i := 0
	for _, secret := range r.decryptionSecrets {
		t.Log(fmt.Sprintf("SecretType:%X, Length:%d, Data:%s", secret.blockInfo.secretsType, secret.blockInfo.secretsLength, secret.payload))
		i++
	}
	if i <= 0 {
		t.Fatal("Can't found decryption secrets")
	}
}
