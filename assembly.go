// Package assembly provides TCP stream re-assembly.
//
// The assembly package implements uni-directional TCP reassembly, for use in
// packet-sniffing applications.  The caller reads packets off the wire, then
// presents them to an Assembler in the form of gopacket.TCP packets
// (code.google.com/p/gopacket).  The Assembler uses a user-supplied
// StreamFactory to create a user-defined Stream interface, then passes packet
// data in stream order to that object.  A concurrency-safe StreamPool keeps
// track of all current Streams being reassembled, so multiple Assemblers may
// run at once to assemble packets while taking advantage of multiple cores.
package assembly

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"sync"
	"time"
)

const invalidSequence = -1
const uint32Max = 0xFFFFFFFF

// Sequence is a TCP sequence number.
type Sequence int64

// Difference defines an ordering for comparing TCP sequences that's safe for
// roll-overs.  It returns:
//    > 0 : if t comes after s
//    < 0 : if t comes before s
//      0 : if t == s
// The number returned is the sequence difference, so 4.Difference(8) will
// return 4.
//
// It handles rollovers by considering any sequence in the first quarter of the
// uint32 space to be after any sequence in the last quarter of that space, thus
// wrapping the uint32 space.
func (s Sequence) Difference(t Sequence) int {
	if s > uint32Max-uint32Max/4 && t < uint32Max/4 {
		t += uint32Max
	} else if t > uint32Max-uint32Max/4 && s < uint32Max/4 {
		s += uint32Max
	}
	return int(t - s)
}

// Add adds an integer to a sequence and returns the resulting sequence.
func (s Sequence) Add(t int) Sequence {
	return (s + Sequence(t)) & uint32Max
}

// Reassembly objects are returned by the assembler in order.
type Reassembly struct {
	// Bytes is the next set of bytes in the stream.  May be empty.
	Bytes []byte
	// Skip is set to true if this reassembly has skipped some number of bytes.
	// This normally occurs if packets were dropped, or if we picked up the stream
	// after it had already started sending data (IE: we start our packet capture
	// mid-stream).
	Skip bool
	// Start is set if this set of bytes has a TCP SYN accompanying it.
	Start bool
	// End is set if this set of bytes has a TCP FIN or RST accompanying it.
	End bool
}

const pageBytes = 1900

// page is used to store TCP data we're not ready for yet (out-of-order
// packets).  Unused pages are stored in and returned from a pageCache, which
// avoids memory allocation.
type page struct {
	Reassembly
	seq        Sequence
	index      int
	prev, next *page
	created    time.Time
	buf        [pageBytes]byte
}

// pageCache is a concurrency-unsafe store of page objects we use to avoid
// memory allocation as much as we can.  It grows but never shrinks.
type pageCache struct {
	free       []*page
	pcSize     int
	size, used int
	pages      [][]page
}

const initialPageCacheSize = 1024

func newPageCache() *pageCache {
	pc := &pageCache{
		free:   make([]*page, 0, initialPageCacheSize),
		pcSize: initialPageCacheSize,
	}
	pc.grow()
	return pc
}

// grow exponentially increases the size of our page cache as much as necessary.
func (c *pageCache) grow() {
	pages := make([]page, c.pcSize)
	c.pages = append(c.pages, pages)
	c.size += c.pcSize
	for i, _ := range pages {
		c.free = append(c.free, &pages[i])
	}
	c.pcSize *= 2
}

// next returns a clean, ready-to-use page object.
func (c *pageCache) next() (p *page) {
	if len(c.free) == 0 {
		c.grow()
	}
	i := len(c.free) - 1
	p, c.free = c.free[i], c.free[:i]
	p.prev = nil
	p.next = nil
	p.created = time.Now()
	p.Bytes = p.buf[:0]
	c.used++
	return p
}

// replace replaces a page into the pageCache.
func (c *pageCache) replace(p *page) {
	c.used--
	c.free = append(c.free, p)
}

// Stream is implemented by the caller to handle incoming reassembled
// TCP data.  Callers create a StreamFactory, then StreamPool uses
// it to create a new Stream for every TCP stream.
//
// assembly will, in order:
//    1) Create the stream via StreamFactory.New
//    2) Call Reassembled 0 or more times, passing in reassembled TCP data in order
//    3) Call ReassemblyComplete one time, after which the stream is dereferenced by assembly.
type Stream interface {
	// Reassembled is called zero or more times.  assembly guarantees
	// that the set of all Reassembly objects passed in during all
	// calls are presented in the order they appear in the TCP stream.
	// Reassembly objects are reused after each Reassembled call,
	// so it's important to copy anything you need out of them
	// (specifically out of Reassembly.Bytes) that you need to stay
	// around after you return from the Reassembled call.
	Reassembled([]Reassembly)
	// ReassemblyComplete is called when assembly decides there is
	// no more data for this Stream, either because a FIN or RST packet
	// was seen, or because the stream has timed out without any new
	// packet data (due to a call to FlushOlderThan).
	ReassemblyComplete()
}

// StreamFactory is used by assembly to create a new stream for each
// new TCP session.
type StreamFactory interface {
	// New should return a new stream for the given TCP key.
	New(netFlow, tcpFlow gopacket.Flow) Stream
}

func (p *StreamPool) connections() []*connection {
	p.mu.RLock()
	conns := make([]*connection, 0, len(p.conns))
	for _, conn := range p.conns {
		conns = append(conns, conn)
	}
	p.mu.RUnlock()
	return conns
}

// FlushOlderThan finds any streams waiting for packets older than
// the given time, and pushes through the data they have (IE: tells
// them to stop waiting and skip the data they're waiting for).
// It also closes any empty streams that haven't seen data since
// the given time.
//
// Returns the number of connections flushed, and of those, the number closed
// because of the flush.
func (a *Assembler) FlushOlderThan(t time.Time) (flushed, closed int) {
	conns := a.connPool.connections()
	closes := 0
	flushes := 0
	for _, conn := range conns {
		conn.mu.Lock()
		if (conn.first != nil && conn.first.created.Before(t)) || (conn.first == nil && conn.lastSeen.Before(t)) {
			flushes++
			a.skipFlush(conn)
			if conn.closed {
				closes++
			}
		}
		conn.mu.Unlock()
	}
	return flushes, closes
}

// FlushAll flushes all remaining data into all remaining connections, closing
// those connections.
func (a *Assembler) FlushAll() {
	for _, conn := range a.connPool.connections() {
		conn.mu.Lock()
		for !conn.closed {
			a.skipFlush(conn)
		}
		conn.mu.Unlock()
	}
}

type key [2]gopacket.Flow

// StreamPool is a concurrency-safe collection of assembly Streams,
// usable by multiple Assemblers to handle packet data over multiple
// goroutines.
type StreamPool struct {
	conns   map[key]*connection
	users   int
	mu      sync.RWMutex
	factory StreamFactory
	free    []*connection
	all     [][]connection
}

func (p *StreamPool) grow() {
	conns := make([]connection, 2048)
	p.all = append(p.all, conns)
	for i, _ := range conns {
		p.free = append(p.free, &conns[i])
	}
}

// NewStreamPool creates a new connection pool.  Streams will
// be created as necessary using the passed-in StreamFactory.
func NewStreamPool(factory StreamFactory) *StreamPool {
	return &StreamPool{
		conns:   make(map[key]*connection),
		factory: factory,
	}
}

const assemblerReturnValueInitialSize = 16

// NewAssembler creates a new assembler.  Pass in the StreamPool
// to use, may be shared across assemblers.
//
// This sets some sane defaults for the assembler options, specifically:
//  MaxBufferedPagesPerConnection: 10
func NewAssembler(pool *StreamPool) *Assembler {
	pool.mu.Lock()
	pool.users++
	pool.mu.Unlock()
	return &Assembler{
		ret:      make([]Reassembly, assemblerReturnValueInitialSize),
		pc:       newPageCache(),
		connPool: pool,
		AssemblerOptions: AssemblerOptions{
			MaxBufferedPagesPerConnection: 10,
		},
	}
}

type connection struct {
	key               key
	pages             int
	first, last       *page
	nextSeq           Sequence
	created, lastSeen time.Time
	stream            Stream
	closed            bool
	mu                sync.Mutex
}

func (c *connection) reset(k key, s Stream) {
	c.key = k
	c.pages = 0
	c.first, c.last = nil, nil
	c.nextSeq = invalidSequence
	c.created = time.Now()
	c.stream = s
	c.closed = false
}

// AssemblerOptions controls the behavior of each assembler.  Modify the
// options of each assembler you create to change their behavior.
type AssemblerOptions struct {
	// MaxBufferedPagesTotal is an upper limit on the total number of pages to
	// buffer while waiting for out-of-order packets.  Once this limit is
	// reached, the assembler will degrade to flushing every connection it
	// gets a packet for.  If <= 0, this is ignored.
	MaxBufferedPagesTotal int
	// MaxBufferedPagesPerConnection is an upper limit on the number of pages
	// buffered for a single connection.  Should this limit be reached for a
	// particular connection, the smallest sequence number will be flushed, along
	// with any contiguous data.  If <= 0, this is ignored.
	MaxBufferedPagesPerConnection int
}

// Assembler handles reassembling TCP streams.  It is not safe for
// concurrency.
//
// The Assembler provides (hopefully) fast TCP stream re-assembly for sniffing
// applications written in Go.  The Assembler uses the following methods to be as
// fast as possible, to keep packet processing speedy:
//
// Avoids Lock Contention
//
// Assemblers locks connections, but each connection has an individual lock, and
// rarely will two Assemblers be looking at the same connection.  Assemblers
// lock the StreamPool when looking up connections, but they use Reader
// locks initially, and only force a write lock if they need to create a new
// connection or close one down.  These happen much less frequently than
// individual packet handling.
//
// Each assembler runs in its own goroutine, and the only state shared between
// goroutines is through the StreamPool.  Thus all internal Assembler state
// can be handled without any locking.
//
// NOTE:  If you can guarantee that packets going to a set of Assemblers will
// contain information on different connections per Assembler (for example,
// they're already hashed by PF_RING hashing or some other hashing mechanism),
// then we recommend you use a seperate StreamPool per Assembler, thus
// avoiding all lock contention.  Only when different Assemblers could receive
// packets for the same Stream should a StreamPool be shared between them.
//
// Avoids Memory Copying
//
// In the common case, handling of a single TCP packet should result in zero
// memory allocations.  The Assembler will look up the connection, figure out
// that the packet has arrived in order, and immediately pass that packet on to
// the appropriate connection's handling code.  Only if a packet arrives out of
// order is its contents copied and stored in memory for later.
//
// Avoids Memory Allocation
//
// Assemblers try very hard to not use memory allocation unless absolutely
// necessary.  Packet data for sequential packets is passed directly to streams
// with no copying or allocation.  Packet data for out-of-order packets is
// copied into reusable pages, and new pages are only allocated rarely when the
// page cache runs out.  Page caches are Assembler-specific, thus not used
// concurrently and requiring no locking.
//
// Internal representations for connection objects are also reused over time.
// Because of this, the most common memory allocation done by the Assembler is
// generally what's done by the caller in StreamFactory.New.  If no allocation
// is done there, then very little allocation is done ever, mostly to handle
// large increases in bandwidth or numbers of connections.
//
// TODO:  The page caches used by an Assembler will grow to the size necessary
// to handle a workload, and currently will never shrink.  This means that
// traffic spikes can result in large memory usage which isn't garbage
// collected when typical traffic levels return.
type Assembler struct {
	AssemblerOptions
	ret      []Reassembly
	pc       *pageCache
	connPool *StreamPool
}

func (p *StreamPool) newConnection(k key, s Stream) (c *connection) {
	if len(p.free) == 0 {
		p.grow()
	}
	index := len(p.free) - 1
	c, p.free = p.free[index], p.free[:index]
	c.reset(k, s)
	return c
}

// getConnection returns a new (locked) connection.
func (p *StreamPool) getConnection(k key) *connection {
	p.mu.RLock()
	conn := p.conns[k]
	p.mu.RUnlock()
	if conn != nil {
		return conn
	}
	s := p.factory.New(k[0], k[1])
	p.mu.Lock()
	conn = p.newConnection(k, s)
	if conn2 := p.conns[k]; conn2 != nil {
		p.mu.Unlock()
		return conn2
	}
	p.conns[k] = conn
	p.mu.Unlock()
	return conn
}

// Assemble reassembles the given TCP packet into its appropriate stream.
// Each Assemble call results in, in order:
//
//    zero or one calls to StreamFactory.New, creating a stream
//    zero or one calls to Reassembled on a single stream
//    zero or one calls to ReassemblyComplete on the same stream
func (a *Assembler) Assemble(netFlow gopacket.Flow, t *layers.TCP) {
	// Ignore empty TCP packets
	if !t.SYN && !t.FIN && !t.RST && len(t.LayerPayload()) == 0 {
		return
	}

	a.ret = a.ret[:0]
	key := key{netFlow, t.TransportFlow()}
	var conn *connection
	// This for loop handles a race condition where a connection will close, lock
	// the connection pool, and remove itself, but before it locked the connection
	// pool it's returned to another Assemble statement.  This should loop 0-1
	// times for the VAST majority of cases.
	for {
		conn = a.connPool.getConnection(key)
		conn.mu.Lock()
		if !conn.closed {
			break
		}
		conn.mu.Unlock()
	}
	conn.lastSeen = time.Now()
	seq, bytes := Sequence(t.Seq), t.Payload
	if t.SYN {
		a.ret = append(a.ret, Reassembly{
			Bytes: bytes,
			Skip:  false,
			Start: true,
		})
		conn.nextSeq = seq.Add(len(bytes) + 1)
	} else if conn.nextSeq == invalidSequence || conn.nextSeq.Difference(seq) > 0 {
		a.insertIntoConn(t, conn)
	} else {
		span := int(seq.Difference(conn.nextSeq))
		if len(bytes) >= span {
			a.ret = append(a.ret, Reassembly{
				Bytes: bytes[span:],
				Skip:  false,
				End:   t.RST || t.FIN,
			})
			conn.nextSeq = seq.Add(len(bytes))
		}
	}
	if len(a.ret) > 0 {
		a.sendToConnection(conn)
	}
	conn.mu.Unlock()
}

func (a *Assembler) sendToConnection(conn *connection) {
	a.addContiguous(conn)
	if conn.stream == nil {
		panic("why?")
	}
	conn.stream.Reassembled(a.ret)
	if a.ret[len(a.ret)-1].End {
		a.closeConnection(conn)
	}
}

func (a *Assembler) addContiguous(conn *connection) {
	for conn.first != nil && conn.first.seq == conn.nextSeq {
		a.addNextFromConn(conn, false)
	}
}

func (a *Assembler) skipFlush(conn *connection) {
	if conn.first == nil {
		a.closeConnection(conn)
	} else {
		a.ret = a.ret[:0]
		a.addNextFromConn(conn, true)
		a.sendToConnection(conn)
	}
}

func (p *StreamPool) remove(conn *connection) {
	p.mu.Lock()
	delete(p.conns, conn.key)
	p.free = append(p.free, conn)
	p.mu.Unlock()
}

func (a *Assembler) closeConnection(conn *connection) {
	conn.stream.ReassemblyComplete()
	conn.closed = true
	a.connPool.remove(conn)
	for p := conn.first; p != nil; p = p.next {
		a.pc.replace(p)
	}
}

// traverseConn traverses our doubly-linked list of pages for the correct
// position to put the given sequence number.  Note that it traverses backwards,
// starting at the highest sequence number and going down, since we assume the
// common case is that TCP packets for a stream will appear in-order, with
// minimal loss or packet reordering.
func (conn *connection) traverseConn(seq Sequence) (prev, current *page) {
	prev = conn.last
	for prev != nil && prev.seq.Difference(seq) < 0 {
		current = prev
		prev = current.prev
	}
	return
}

// pushBetween inserts the doubly-linked list first-...-last in between the
// nodes prev-next in another doubly-linked list.  If prev is nil, makes first
// the new first page in the connection's list.  If next is nil, makes last the
// new last page in the list.  first/last may point to the same page.
func (conn *connection) pushBetween(prev, next, first, last *page) {
	// Maintain our doubly linked list
	if next == nil || conn.last == nil {
		conn.last = last
	} else {
		last.next = next
		next.prev = last
	}
	if prev == nil || conn.first == nil {
		conn.first = first
	} else {
		first.prev = prev
		prev.next = first
	}
}

func (a *Assembler) insertIntoConn(t *layers.TCP, conn *connection) {
	p, p2 := a.pagesFromTcp(t)
	prev, current := conn.traverseConn(Sequence(t.Seq))
	conn.pushBetween(prev, current, p, p2)
	conn.pages++
	if (a.MaxBufferedPagesPerConnection > 0 && conn.pages >= a.MaxBufferedPagesPerConnection) ||
		(a.MaxBufferedPagesTotal > 0 && a.pc.used >= a.MaxBufferedPagesTotal) {
		a.addNextFromConn(conn, true)
	}
}

// pagesFromTcp creates a page (or set of pages) from a TCP packet.  Note that
// it should NEVER receive a SYN packet, as it doesn't handle sequences
// correctly.
//
// It returns the first and last page in its doubly-linked list of new pages.
func (a *Assembler) pagesFromTcp(t *layers.TCP) (p, p2 *page) {
	first := a.pc.next()
	current := first
	seq, bytes := Sequence(t.Seq), t.Payload
	for {
		length := min(len(bytes), pageBytes)
		current.Bytes = current.buf[:length]
		copy(current.Bytes, bytes)
		current.seq = seq
		bytes = bytes[length:]
		if len(bytes) == 0 {
			break
		}
		seq = seq.Add(length)
		current.next = a.pc.next()
		current.next.prev = current
		current = current.next
	}
	current.End = t.RST || t.FIN
	return first, current
}

// addNextFromConn pops the first page from a connection off and adds it to the
// return array.
func (a *Assembler) addNextFromConn(conn *connection, skip bool) {
	conn.first.Skip = skip
	a.ret = append(a.ret, conn.first.Reassembly)
	conn.nextSeq = conn.first.seq.Add(len(conn.first.Bytes))
	a.pc.replace(conn.first)
	if conn.first == conn.last {
		conn.first = nil
		conn.last = nil
	} else {
		conn.first = conn.first.next
		conn.first.prev = nil
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
