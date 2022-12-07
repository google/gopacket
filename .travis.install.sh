#!/bin/bash

set -ev

go get github.com/kubeshark/gopacket
go get github.com/kubeshark/gopacket/layers
go get github.com/kubeshark/gopacket/tcpassembly
go get github.com/kubeshark/gopacket/reassembly
go get github.com/kubeshark/gopacket/pcapgo
