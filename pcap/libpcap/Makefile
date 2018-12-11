###############################################################################
#
# Makefile: Makefile to build / customize libpcap for gopacket
#
# Written by Lennart Elsen and Fabian Kohn, November 2018
#
################################################################################

SHELL := /bin/bash

# downloader used for grabbing the external code. Change this if it does not
# correspond to the usual way you download files on your system
DOWNLOAD	= curl --progress-bar -L --url

# pcap libraries
PCAP_VERSION = 1.9.0
PCAP		 = libpcap-$(PCAP_VERSION)
PCAP_SITE	 = http://www.tcpdump.org/release
PCAP_DIR	 := /tmp/$(PCAP)

fetch:

	echo "*** downloading $(PCAP) ***"
	$(DOWNLOAD) $(PCAP_SITE)/$(PCAP).tar.gz -O

unpack:

	echo "*** unpacking dependency $(PCAP) ***"
	tar xf $(PCAP).tar.gz

patch:

	echo "*** patching dependency $(PCAP) ***"
	patch -Np0 < libpcap-$(PCAP_VERSION).patch

configure:
	echo "*** configuring dependency $(PCAP) ***"
	cd $(PCAP); sh configure --prefix=$(PWD)/$(PCAP)/install --quiet >> /dev/null

compile:

	echo "*** compiling $(PCAP) ***"
	cd $(PCAP); make -s > /dev/null; make -s install > /dev/null

install:

	echo "*** installing $(PCAP) ***"
	cp $(PCAP)/install/lib/libpcap.a ./libpcap_linux.a
	cp -r $(PCAP)/install/include/* ./

clean:

	echo "*** removing $(PCAP) ***"
	rm -rf $(PCAP) $(PCAP).tar.gz

all: clean fetch unpack patch configure compile install

.SILENT:
