include $(GOROOT)/src/Make.inc

TARG=pcap
GOFILES=decode.go\
	io.go
CGOFILES=pcap.go
CGO_LDFLAGS=-lpcap
CLEANFILES=pcaptest tcpdump

include $(GOROOT)/src/Make.pkg

pcaptest: pcaptest.go install
	$(GC) pcaptest.go
	$(LD) -o $@ pcaptest.$(O)

tcpdump: tcpdump.go install
	$(GC) tcpdump.go
	$(LD) -o $@ tcpdump.$(O)

pass: pass.go install
	$(GC) pass.go
	$(LD) -o $@ pass.$(O)
