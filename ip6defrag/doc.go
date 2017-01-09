PcapParser
=========================
PcapParser is a program aiming at defragment ip fragments and ressembling tcp of DNS packages. Now this program only reads PCAP file as input and output a PCAP file. More features might be added if there are new requirements.


Installation
============
This program is written in Golang, so make sure you get Golang installed before you installing this program. 

This program depends on 'libpcap' library, which can be downloaded from the
[tcpdump](http://www.tcpdump.org/) project page. On a Debian or
Debian-derived system installation will look something like this:

    $ sudo apt install libpcap-dev
Which you also need is a Golang network parse library called Gopacket from google, 
you can easily get it using go get command

    $ go get github.com/google/gopacket
Then you can easily get source code in same way

    $ go get https://github.com/RunxiaWan/PcapParser

Build gopacket first

    $ go build github.com/google/gopacket

Then build 'PcapParser'

    $ go build github.com/RunxiaWan/PcapParser

Running
=======
You can simply run PcapParser by

    ./PcapParser -in input -out output
'input' is the file path of input pcap file and output is the file path of output pcap file. To see the dicription of Other option:

    ./PcapParser -h
You may all want to put PcapParser into /user/sbin for using it as a command.

If have any suggestion to improve the program please contact:wanrunxia@aliyun.com
