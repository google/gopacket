#!/bin/bash

set -ev

go test github.com/xiaofsec/gopacket
go test github.com/xiaofsec/gopacket/layers
go test github.com/xiaofsec/gopacket/tcpassembly
go test github.com/xiaofsec/gopacket/reassembly
go test github.com/xiaofsec/gopacket/pcapgo
go test github.com/xiaofsec/gopacket/pcap
sudo $(which go) test github.com/xiaofsec/gopacket/routing
