// Copyright 2012 Google, Inc. All rights reserved.

// Package gopacket provides packet decoding for the Go language.
//
// Basic Usage
//
// gopacket takes in packet data as a []byte, and decodes it into a packet with
// a non-zero number of "layers", with each layer corresponding a protocol
// within the bytes.  Once a packet has been decoded, the layers of that packet
// can be requested from the packet.
//
//  // Decode a packet
//  packet := gopacket.NewPacket(myPacketData, gopacket.LinkTypeEthernet, gopacket.Default)
//  // Get the TCP layer from this packet
//  if tcpLayer := packet.Layer(gopacket.LayerTypeTCP); tcpLayer != nil {
//    fmt.Println("This is a TCP packet!")
//    // Get actual TCP data from this layer
//    tcp, _ := tcpLayer.(*gopacket.TCP)
//    fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
//  }
//  // Iterate over all layers, printing out each layer type
//  for layer := range packet.Layers() {
//    fmt.Println("PACKET LAYER:", layer.LayerType())
//  }
//
// Packets can be decoded from a number of starting points.  Many of our base
// types implement Decoder, which allow us to decode packets for which
// we don't have full data.
//
//  // Decode an ethernet packet
//  ethP := gopacket.NewPacket(p1, gopacket.LinkTypeEthernet, gopacket.Default)
//  // Decode an IPv6 header and everything it contains
//  ipP := gopacket.NewPacket(p2, gopacket.EthernetTypeIPv6, gopacket.Default)
//  // Decode a TCP header and its payload
//  tcpP := gopacket.NewPacket(p3, gopacket.IPProtocolTCP, gopacket.Default)
//
// NOTE:  NewPacket takes in a byte slice as its first argument.  Changing the
// data within that slice WILL invalidate the layers in the packet:
//
//  myData := [200]byte{...}
//  p := gopacket.NewPacket(myData[:], ...)
//  myData[10] = 3  // Invalidates p and all of its layers
//
// If you plan on using a slice multiple times for input, and you want to
// keep packets around after it has been reused, you must copy out your data:
//
//  myInputBuffer := [200]byte{}
//  for {
//    bytesRead := readPacketDataInto(myInputBuffer[:])
//    packetCopy := make([]byte, bytesRead)
//    copy(packetCopy, myInputBuffer[:])
//    p := gopacket.NewPacket(packetCopy, ...)
//  }
//
// Lazy Decoding
//
// gopacket optionally decodes packet data lazily, meaning it
// only decodes a packet layer when it needs to to handle a function call.
//
//  // Create a packet, but don't actually decode anything yet
//  packet := gopacket.NewPacket(myPacketData, gopacket.LinkTypeEthernet, gopacket.Lazy)
//  // Now, decode the packet up to the first IPv4 layer found but no further.
//  // If no IPv4 layer was found, the whole packet will be decoded looking for
//  // it.
//  ip4 := packet.Layer(gopacket.LayerTypeIPv4)
//  // Decode all layers and return them.  The layers up to the first IPv4 layer
//  // are already decoded, and will not require decoding a second time.
//  layers := packet.Layers()
//
// Lazily-decoded packets are not concurrency-safe.  If a packet is used
// in multiple goroutines concurrently, don't use gopacket.Lazy.  Then gopacket
// will decode the packet fully, and all future function calls won't mutate the
// object.
//
// NoCopy Decoding
//
// By default, gopacket will copy the slice passed to NewPacket and store the
// copy within the packet, so future mutations to the bytes underlying the slice
// don't affect the packet and its layers.  If you can guarantee that the
// underlying slice bytes won't be changed, you can use NoCopy to tell
// gopacket.NewPacket, and it'll use the passed-in slice itself.
//
//  // This channel returns new byte slices, each of which points to a new
//  // memory location that's guaranteed immutable for the duration of the
//  // packet.
//  for data := range myByteSliceChannel {
//    p := gopacket.NewPacket(data, gopacket.LinkTypeEthernet, gopacket.NoCopy)
//    doSomethingWithPacket(p)
//  }
//
// The fastest method of decoding is to use both Lazy and NoCopy, but note from
// the many caveats above that for some implementations they may be dangerous
// either or both may be dangerous.
//
// Pointers To Known Layers
//
// During decoding, certain layers are stored in the packet as well-known
// layer types.  For example, IPv4 and IPv6 are both considered NetworkLayer
// layers, while TCP and UDP are both TransportLayer layers.  We support 4
// layers, corresponding to the 4 layers of the TCP/IP layering scheme (roughly
// anagalous to layers 2, 3, 4, and 7 of the OSI model).  To access these,
// you can use the packet.LinkLayer, packet.NetworkLayer,
// packet.TransportLayer, and packet.ApplicationLayer functions.  Each of
// these functions returns a corresponding interface
// (gopacket.{Link,Network,Transport,Application}Layer).  The first three
// provide methods for getting src/dst addresses for that particular layer,
// while the final layer provides a Payload function to get payload data.
// This is helpful, for example, to get payloads for all packets regardless
// of their underlying data type:
//
//  // Get packets from some source
//  for packet := range someSource {
//    if app := packet.ApplicationLayer(); app != nil {
//      if strings.Contains(string(app.Payload()), "magic string") {
//        fmt.Println("Found magic string in a packet!")
//      }
//    }
//  }
//
// A particularly useful layer is ErrorLayer, which is set whenever there's
// an error parsing part of the packet.
//
//  packet := gopacket.NewPacket(myPacketData, gopacket.LinkTypeEthernet, gopacket.Default)
//  if err := packet.ErrorLayer(); err != nil {
//    fmt.Println("Error decoding some part of the packet:", err)
//  }
//
// Note that we don't return an error from NewPacket because we may have decoded
// a number of layers successfully before running into our erroneous layer.  You
// may still be able to get your Ethernet and IPv4 layers correctly, even if
// your TCP layer is malformed.
//
// Flow And Endpoint
//
// gopacket has two useful objects, Flow and Endpoint, for communicating in a protocol
// independent manner the fact that a packet is coming from A and going to B.
// The general layer types LinkLayer, NetworkLayer, and TransportLayer all provide
// methods for extracting their flow information, without worrying about the type
// of the underlying Layer.
//
// A Flow is a simple object made up of a set of two Endpoints, one source and one
// destination.  It details the sender and receiver of the Layer of the Packet.
//
// An Endpoint is a LayerType and an address associated with that type.  For
// example, for LayerTypeIPv4, an Endpoint contains the IP address bytes for a v4
// IP packet.  A Flow can be broken into Endpoints, and Endpoints can be combined
// into Flows:
//
//  packet := gopacket.NewPacket(myPacketData, gopacket.LinkTypeEthernet, gopacket.Lazy)
//  netFlow := packet.NetworkLayer().NetworkFlow()
//  src, dst := netFlow.Endpoints()
//  reverseFlow := gopacket.NewFlow(dst, src)
//
// Both Endpoint and Flow objects can be used as map keys, and the equality
// operator can compare them, so you can easily group together all packets
// based on endpoint criteria:
//
//  flows := map[gopacket.Endpoint]chan gopacket.Packet
//  packet := gopacket.NewPacket(myPacketData, gopacket.LinkTypeEthernet, gopacket.Lazy)
//  // Send all TCP packets to channels based on their destination port.
//  if tcp := packet.Layer(gopacket.LayerTypeTCP); tcp != nil {
//    flows[tcp.TransportFlow().Dst()] <- packet
//  }
//  // Look for all packets with the same source and destination network address
//  if net := packet.NetworkLayer(); net != nil {
//    src, dst := net.NetworkFlow().Endpoints()
//    if src == dst {
//      fmt.Println("Fishy packet has same network source and dst: %s", src)
//    }
//  }
//  // Find all packets coming from UDP port 1000 to UDP port 500
//  interestingFlow := gopacket.NewFlow(gopacket.NewUDPPortEndpoint(1000), gopacket.NewUDPPortEndpoint(500))
//  if t := packet.NetworkLayer(); t != nil && t.TransportFlow() == interestingFlow {
//    fmt.Println("Found that UDP flow I was looking for!")
//  }
//
// Implementing Your Own Decoder
//
// If your network has some strange encapsulation, you can implement your own
// decoder.  In this example, we handle Ethernet packets which are encapsulated
// in a 4-byte header.
//
//  // Create a layer type, should be unique and high, so it doesn't conflict.
//  const MyLayerType LayerType = 1354214661
//
//  // Implement my layer
//  type MyLayer struct {
//    StrangeHeader []byte
//  }
//  func (m MyLayer) LayerType() LayerType { return MyLayerType }
//
//  // Now implement a decoder... this one strips off the first 4 bytes of the
//  // packet.
//  type MyDecoder struct {}
//  func (m MyDecoder) Decode(data []byte) (out gopacket.DecodeResult, err error) {
//    // Create my layer
//    out.DecodedLayer = &MyLayer{data[:4]}
//    // Set which bytes we have left to decode
//    out.RemainingBytes = data[4:]
//    // Determine how to handle the rest of the packet
//    out.NextDecoder = gopacket.LinkTypeEthernet
//    return
//  }
//
//  // Finally, decode your packets:
//  p := gopacket.NewPacket(data, &MyDecoder{}, gopacket.Lazy)
//
// Currently Supported Protocols
//
// gopacket supports the following packet layers so far.  Each protocol is
// encoded in the struct with the same name.
//  Protocol                Type Name    Implements
//  ---------------------------------------------------------------------------
//  Ethernet                Ethernet     LinkLayer
//  PPP                     PPP          LinkLayer
//  ARP                     ARP
//  802.11Q vlan tagging    Dot1Q
//  MPLS                    MPLS
//  IP version 4            IPv4         NetworkLayer
//  IP version 6            IPv6         NetworkLayer
//  ICMP                    ICMP
//  TCP                     TCP          TransportLayer
//  UDP                     UDP          TransportLayer
//  SCTP                    SCTP         TransportLayer
package gopacket
