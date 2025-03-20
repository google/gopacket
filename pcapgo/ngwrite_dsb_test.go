package pcapgo

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"io"
	"math"
	"net"
	"os"
	"testing"
)

// TestNgWriterDSB tests the WriteDecryptionSecretsBlock function.
func TestNgWriterDSB(t *testing.T) {

	// Test that we can read a DSB file.
	pcapngFile := "tests/le/test300.pcapng"
	tlsKey := "CLIENT_RANDOM 65bafa1a1a37aebce6ab7af420f9a6ca10513ad1d53aececbe831a28982a5c18 8d1e0c21e653f8e0720c987c3daaca094ff6eb1ccc9e15a8384a214139dfdcf25f0ee77ac81250c7a11b8da561313528\n"
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
	for {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			t.Log("ReadPacketData returned EOF")
			break
		}
		b.data = append(b.data, data)
		b.ci = append(b.ci, ci)
	}

	t.Logf("bigEndian %t", r.bigEndian)
	t.Logf("len(b.data) %d", len(b.data))
	t.Logf("len(b.ci) %d", len(b.ci))

	tmpPcapng := "tests/dbs_tmp.pcapng"
	writer, err := createPcapng(tmpPcapng)

	//write Decryption Secrets Block
	err = writer.WriteDecryptionSecretsBlock(DSB_SECRETS_TYPE_TLS, []byte(tlsKey))
	if err != nil {
		t.Fatal("Couldn't write Decryption Secrets Block:", err)
	}

	for i, ci := range b.ci {
		err = writer.WritePacket(ci, b.data[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	err = writer.Flush()
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Wrote Decryption Secrets Block.")

	// TODO check DSB

	os.Remove(tmpPcapng)
}

func createPcapng(pcapngFilename string) (*NgWriter, error) {
	pcapFile, err := os.OpenFile(pcapngFilename, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("error creating pcap file: %v", err)
	}

	pcapOption := NgWriterOptions{
		SectionInfo: NgSectionInfo{
			Hardware:    "eCapture Hardware",
			OS:          "",
			Application: "ecapture.lua",
			Comment:     "see https://ecapture.cc for more information.",
		},
	}
	// write interface description
	ngIface := NgInterface{
		Name:       "eth0",
		Comment:    "gopacket: https://github.com/google/gopacket",
		Filter:     "",
		LinkType:   layers.LinkTypeEthernet,
		SnapLength: uint32(math.MaxUint16),
	}

	pcapWriter, err := NewNgWriterInterface(pcapFile, ngIface, pcapOption)
	if err != nil {
		return nil, err
	}

	netIfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	// insert other interfaces into pcapng file
	for _, iface := range netIfs {
		ngIface = NgInterface{
			Name:       iface.Name,
			Comment:    "see https://ecapture.cc for more information.",
			Filter:     "",
			LinkType:   layers.LinkTypeEthernet,
			SnapLength: uint32(math.MaxUint16),
		}

		_, err = pcapWriter.AddInterface(ngIface)
		if err != nil {
			return nil, err
		}
	}
	return pcapWriter, nil
}
