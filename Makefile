include $(GOROOT)/src/Make.$(GOARCH)

TARG=pcap

CGOFILES=pcap.go

CGO_LDFLAGS=-lpcap

include $(GOROOT)/src/Make.pkg

pcaptest: pcaptest.go install
	$(GC) pcaptest.go
	$(LD) -o $@ pcaptest.$(O)
