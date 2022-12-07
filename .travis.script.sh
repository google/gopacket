#!/bin/bash

set -ev

go test github.com/kubeshark/gopacket
go test github.com/kubeshark/gopacket/layers
go test github.com/kubeshark/gopacket/tcpassembly
go test github.com/kubeshark/gopacket/reassembly
go test github.com/kubeshark/gopacket/pcapgo
go test github.com/kubeshark/gopacket/pcap
sudo $(which go) test github.com/kubeshark/gopacket/routing
