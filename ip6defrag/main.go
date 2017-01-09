package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"log"
	"os"
)

func readSource(source *gopacket.PacketSource, tcpPack chan gopacket.Packet, tcpFinished chan bool,
	normalPack chan gopacket.Packet) {

	v4defragger := ip4defrag.NewIPv4Defragmenter()
	v6defragger := NewIPv6Defragmenter()

	n := 0
	for packet := range source.Packets() {
		n++
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcpPack <- packet
			//fmt.Printf("%d: TCP packet\n", n)
			// send packet to TCP assembler
		} else {
			v6Layer := packet.Layer(layers.LayerTypeIPv6)
			if v6Layer != nil {
				//fmt.Printf("%d: IPv6 packet\n", n)
				v6frag := packet.Layer(layers.LayerTypeIPv6Fragment)
				if v6frag != nil {
					defragmentedPacket, err := v6defragger.DefragIPv6(packet)
					// handle any errors
					if err != nil {
						// TODO: log the error
						continue
					}
					// if defragmentedPacket is nil, reassembly not yet done
					if defragmentedPacket == nil {
						continue
					}
					// if we got a defragmented packet, process it
					v6Layer = defragmentedPacket.Layer(layers.LayerTypeIPv6)
				}

				ipv6 := v6Layer.(*layers.IPv6)
				IPserializeBuffer := gopacket.NewSerializeBuffer()
				buf, _ := IPserializeBuffer.PrependBytes(len(ipv6.Payload))
				copy(buf, ipv6.Payload)
				ops := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}
				ipv6.SerializeTo(IPserializeBuffer, ops)
				sendPack := gopacket.NewPacket(IPserializeBuffer.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
				err := sendPack.ErrorLayer()
				if err != nil {
					fmt.Printf("Packet #%d problem building IPv6 packet - %s\n", n, err)
				}
				sendPack.Metadata().CaptureLength = len(sendPack.Data())
				sendPack.Metadata().Length = len(sendPack.Data())
				normalPack <- sendPack
			} else {
				v4Layer := packet.Layer(layers.LayerTypeIPv4)
				if v4Layer != nil {
					//fmt.Printf("%d: IPv4 packet\n", n)
					ip := v4Layer.(*layers.IPv4)

					if isFragmentedV4(ip) {
						//fmt.Printf("IPv4 fragmented\n")
						var err error
						ip, err = v4defragger.DefragIPv4(ip)
						// handle any errors
						if err != nil {
							fmt.Printf("IPv4 error in fragmentation\n")
							// TODO: log the error
							continue
						}
						// if returned Layer is nil, reassembly not yet done
						if ip == nil {
							//fmt.Printf("IPv4 reassembly not done\n")
							continue
						}
						//fmt.Printf("IPv4 reassembly complete!\n")
					}

					// build a new packet to remove Ethernet framing if needed
					IPserializeBuffer := gopacket.NewSerializeBuffer()
					buf, _ := IPserializeBuffer.PrependBytes(len(ip.Payload))
					copy(buf, ip.Payload)
					ops := gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					}
					ip.SerializeTo(IPserializeBuffer, ops)
					sendPack := gopacket.NewPacket(IPserializeBuffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
					err := sendPack.ErrorLayer()
					if err != nil {
						fmt.Printf("Packet #%d problem building IPv4 packet - %s\n", n, err)
					}
					sendPack.Metadata().CaptureLength = len(sendPack.Data())
					sendPack.Metadata().Length = len(sendPack.Data())
					normalPack <- sendPack
				} else {
					//fmt.Printf("%d: Skipping non-IP packet\n", n)
					// Neither IPv6 nor IPv4.
					// Since we do not preserve the Ethernet (or other)
					// framing, we cannot include these packets in our output.
					// Remove from out output stream.
				}
			}
		}
	}

	// stop TCP processing and wait for it to be done
	// XXX: do we need to wait some time after this for stream processing to finish?
	// TODO: see if there is a "wait for streams to be done" method
	close(tcpPack)
	<-tcpFinished

	// finished reading
	close(normalPack)
}

func pcapWrite(w *pcapgo.Writer, pack chan gopacket.Packet) {
	for packet := range pack {
		err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()) // write the payload
		if err != nil {
			fmt.Println("error in Write File: ", err)
		}
	}
}

func isFragmentedV4(ip *layers.IPv4) bool {
	// don't defrag packets with DF (Don't Fragment) flag
	if (ip.Flags & layers.IPv4DontFragment) != 0 {
		return false
	}
	// don't defrag packets that are not fragmented
	if ((ip.Flags & layers.IPv4MoreFragments) == 0) && (ip.FragOffset == 0) {
		return false
	}
	return true
}

func tcpAssemble(tcpPack chan gopacket.Packet, tcpFinished chan bool, assembler *tcpassembly.Assembler) {
	for packet := range tcpPack {
		tcp := packet.TransportLayer().(*layers.TCP)
		assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
	}
	tcpFinished <- true
}

type DNSStreamFactory struct {
	normal chan gopacket.Packet
}

// httpStream will handle the actual decoding of http requests.
type dnsStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *DNSStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &dnsStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run(h.normal) // Important... we must guarantee that data from the reader stream is read.
	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *dnsStream) run(normalpack chan gopacket.Packet) {
	for {
		len_buf := make([]byte, 2, 2)
		nread, err := io.ReadFull(&h.r, len_buf)
		if nread < 2 || (err != nil && err != io.EOF) {
			// needs error handle there
			//		fmt.Println("error in reading first two bytes: %s", err)
			break
		}
		msg_len := uint(len_buf[0])<<8 | uint(len_buf[1])
		//	fmt.Printf("msg_len:%d\n", msg_len)
		msg_buf := make([]byte, msg_len, msg_len)
		nread, err = io.ReadFull(&h.r, msg_buf)
		if err != nil {
			//		fmt.Println("error in reading full tcp data: %s", err)
			break
		}
		h.createPacket(msg_buf, normalpack)
	}
}
func (h *dnsStream) createPacket(msg_buf []byte, normalPack chan gopacket.Packet) {
	var sourcePort, destPort int16
	// read the port from transport flow
	b_buf := bytes.NewBuffer(h.transport.Src().Raw())
	binary.Read(b_buf, binary.BigEndian, &sourcePort)
	b_buf = bytes.NewBuffer(h.transport.Dst().Raw())
	binary.Read(b_buf, binary.BigEndian, &destPort)
	//new a UDP layer
	udpLayer := layers.UDP{
		BaseLayer: layers.BaseLayer{
			Contents: []byte{},
			Payload:  msg_buf,
		},
		SrcPort:  layers.UDPPort(sourcePort),
		DstPort:  layers.UDPPort(destPort),
		Length:   1024,
		Checksum: 30026,
	}
	UDPNewSerializBuffer := gopacket.NewSerializeBuffer() // this buffer could be used as a payload of IP layer
	udpBuffer, _ := UDPNewSerializBuffer.PrependBytes(len(msg_buf))

	copy(udpBuffer, msg_buf)

	ops := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if h.net.EndpointType() == layers.EndpointIPv4 {
		ip_checksum := layers.IPv4{}
		ip_checksum.Version = 4
		// XXX: TTL should be copied from the original packets somehow
		ip_checksum.TTL = 64
		ip_checksum.SrcIP = h.net.Src().Raw()
		ip_checksum.DstIP = h.net.Dst().Raw()
		udpLayer.SetNetworkLayerForChecksum(&ip_checksum)
	} else {
		ip6_checksum := layers.IPv6{}
		ip6_checksum.Version = 6
		ip6_checksum.NextHeader = layers.IPProtocolUDP
		// XXX: HopLimit should be copied from the original packets somehow
		ip6_checksum.HopLimit = 64
		ip6_checksum.SrcIP = h.net.Src().Raw()
		ip6_checksum.DstIP = h.net.Dst().Raw()
		udpLayer.SetNetworkLayerForChecksum(&ip6_checksum)
	}
	err := udpLayer.SerializeTo(UDPNewSerializBuffer, ops)
	if err != nil {
		fmt.Print("error in create udp Layer")
		return
		//err = nil
		//	need err handle there
	}

	if h.net.EndpointType() == layers.EndpointIPv4 { // if it is from ipv4, construct a ipv4 layer
		ip := layers.IPv4{
			BaseLayer: layers.BaseLayer{
				Contents: []byte{},
				Payload:  UDPNewSerializBuffer.Bytes(),
			},
			Version:    4,
			IHL:        0,
			TOS:        0,
			Length:     0,
			Id:         0,
			Flags:      0,
			FragOffset: 0,
			// XXX: TTL should be copied from the original packets somehow
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			Checksum: 0,
			SrcIP:    h.net.Src().Raw(),
			DstIP:    h.net.Dst().Raw(),
			Options:  []layers.IPv4Option{},
			Padding:  []byte{},
		}
		//serialize it and use the serialize buffer to new packet
		IPserializeBuffer := gopacket.NewSerializeBuffer()

		ipBuffer, _ := IPserializeBuffer.PrependBytes(len(UDPNewSerializBuffer.Bytes()))
		copy(ipBuffer, UDPNewSerializBuffer.Bytes())
		err = ip.SerializeTo(IPserializeBuffer, ops)
		if err != nil {
			fmt.Print("error in create ipv4 Layer")
			return
			//err = nil
			//	need err handle there
		}

		resultPack := gopacket.NewPacket(IPserializeBuffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
		resultPack.Metadata().CaptureLength = len(resultPack.Data())
		resultPack.Metadata().Length = len(resultPack.Data())
		//seems the capture length is 0 so the pcapwrite cannot write it, try to give them a write value
		normalPack <- resultPack
		//fmt.Printf("built IPv4 packet from TCP layer\n")
		return

	} else if h.net.EndpointType() == layers.EndpointIPv6 {
		// if it is in IPV6 contruct ipv6 packet
		ip := layers.IPv6{
			BaseLayer: layers.BaseLayer{
				Contents: []byte{},
				Payload:  UDPNewSerializBuffer.Bytes(),
			},
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       0,
			NextHeader:   layers.IPProtocolUDP,
			// XXX: HopLimit should be copied from the original packets somehow
			HopLimit: 64,
			SrcIP:    h.net.Src().Raw(),
			DstIP:    h.net.Dst().Raw(),
			HopByHop: nil,
			// hbh will be pointed to by HopByHop if that layer exists.
		}
		IPserializeBuffer := gopacket.NewSerializeBuffer()
		ipBuffer, _ := IPserializeBuffer.PrependBytes(len(UDPNewSerializBuffer.Bytes()))
		copy(ipBuffer, UDPNewSerializBuffer.Bytes())
		err := ip.SerializeTo(IPserializeBuffer, ops)
		if err != nil {
			fmt.Print("error in create IPv6 Layer")
			return
		}

		resultPack := gopacket.NewPacket(IPserializeBuffer.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
		resultPack.Metadata().CaptureLength = len(resultPack.Data())
		resultPack.Metadata().Length = len(resultPack.Data())
		//seems the capture length is 0 so the pcapwrite cannot write it, try to give them a write value
		//fmt.Printf("built IPv6 packet from TCP layer\n")
		normalPack <- resultPack
		return
	} else {
		// This should not be possible, since we only add packets to our TCP reassembler
		// from our IPv4 or IPv6 handlers.
		fmt.Printf("unknown layer type %d\n", h.net.EndpointType())
		return
	}
}
func main() {
	var FilePathInput string
	var FilePathOutput string
	flag.StringVar(&FilePathInput, "in", "", "the path of PCAP file")
	flag.StringVar(&FilePathOutput, "out", "", "the output file")
	flag.Parse() // in mind if we need to do search in file.
	if FilePathInput == "" || FilePathOutput == "" {
		flag.PrintDefaults()
		return
	}

	// open our input pcap file
	var Input *os.File
	var err error
	if FilePathInput == "-" {
		Input = os.Stdin
	} else {
		Input, err = os.Open(FilePathInput)
		if err != nil {
			log.Fatalf("Error with os.Open('%s'); %v", FilePathInput, err)
		}
		defer Input.Close()
	}
	pcap_file, err := pcapgo.NewReader(Input)
	if err != nil {
		log.Fatalf("Error with pcapgo.NewReader(Input); %v", err)
	}
	packetSource := gopacket.NewPacketSource(pcap_file, pcap_file.LinkType())

	// open our output pcap file
	var Output *os.File
	if FilePathOutput == "-" {
		Output = os.Stdout
	} else {
		Output, err = os.Create(FilePathOutput)
		if err != nil {
			log.Fatalf("Error with os.Create('%s'); %v", FilePathOutput, err)
		}
		defer Output.Close()
	}
	w := pcapgo.NewWriter(Output)
	w.WriteFileHeader(65536, layers.LinkTypeRaw)

	// channel used to write packets
	normalPack := make(chan gopacket.Packet, 5)

	// setup for TCP reassembly
	tcpPack := make(chan gopacket.Packet, 5) // maybe need change buffersize for chan
	streamFactory := &DNSStreamFactory{normal: normalPack}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	tcpFinished := make(chan bool)
	go tcpAssemble(tcpPack, tcpFinished, assembler)

	// read our packets in a background goroutine
	go readSource(packetSource, tcpPack, tcpFinished, normalPack)

	// collect packets and write them
	pcapWrite(w, normalPack)
}
