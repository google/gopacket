package assembly

import (
	"fmt"
	"net"
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
	// Seq is the current TCP sequence for this reassembly.
	Seq Sequence
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

var zeros []byte = make([]byte, 12)

// Key is a unique identifier for a TCP stream.
type Key struct {
	Version          byte // IP version, 4 or 6
	SrcIP, DstIP     [16]byte
	SrcPort, DstPort uint16
}

// Reset resets the given key with new source/destination IPs/ports.
func (k *Key) Reset(sip, dip net.IP, sp, dp uint16) {
	if len(sip) != len(dip) {
		panic("IP lengths don't match")
	}
	oldVersion := k.Version
	switch len(sip) {
	case 4:
		k.Version = 4
		copy(k.SrcIP[:4], sip)
		copy(k.DstIP[:4], dip)
		if oldVersion != 4 {
			copy(k.SrcIP[4:], zeros)
			copy(k.DstIP[4:], zeros)
		}
	case 16:
		k.Version = 6
		copy(k.SrcIP[:], sip)
		copy(k.DstIP[:], dip)
	default:
		panic("Invalid IP length")
	}
	k.SrcPort = sp
	k.DstPort = dp
}

// TCP is the set of fields required from a TCP packet for reassembly.
type TCP struct {
	Key           Key
	Seq           Sequence
	SYN, FIN, RST bool
	Bytes         []byte
}

// Stream is implemented by the caller to handle incoming reassembled
// TCP data.  Callers create a StreamFactory, then ConnectionPool uses
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
	New(k Key) Stream
}

func (p *ConnectionPool) connections() []*connection {
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
func (a *Assembler) FlushOlderThan(t time.Time) {
	start := time.Now()
	fmt.Println("Flushing connections older than", t)
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
	fmt.Println("Flush completed in", time.Since(start), "closed", closes, "flushed", flushes)
}

// ConnectionPool is a concurrency-safe collection of assembly Streams,
// usable by multiple Assemblers to handle packet data over multiple
// goroutines.
type ConnectionPool struct {
	conns   map[Key]*connection
	users   int
	mu      sync.RWMutex
	factory StreamFactory
}

// NewConnectionPool creates a new connection pool.  Streams will
// be created as necessary using the passed-in StreamFactory.
func NewConnectionPool(factory StreamFactory) *ConnectionPool {
	return &ConnectionPool{
		conns:   make(map[Key]*connection),
		factory: factory,
	}
}

// NewAssembler creates a new assembler.  Its arguments are:
//    max:  The maximum number of packets to buffer total.
//    maxPer:  The maximum number of packets to buffer for a single connection.
//    pool:  The ConnectionPool to use, may be shared across assemblers.
func NewAssembler(max, maxPer int, pool *ConnectionPool) *Assembler {
	pool.mu.Lock()
	pool.users++
	pool.mu.Unlock()
	return &Assembler{
		ret:            make([]Reassembly, maxPer+1),
		pc:             newPageCache(),
		connPool:       pool,
		maxBuffered:    max,
		maxBufferedPer: maxPer,
	}
}

type connection struct {
	key               Key
	pages             int
	first, last       *page
	nextSeq           Sequence
	created, lastSeen time.Time
	stream            Stream
	closed            bool
	mu                sync.Mutex
}

// Assembler handles reassembling TCP streams.  It is not safe for
// concurrency.
type Assembler struct {
	ret            []Reassembly
	pc             *pageCache
	maxBuffered    int
	maxBufferedPer int
	connPool       *ConnectionPool
}

func (p *ConnectionPool) newConnection(k *Key) *connection {
	return &connection{
		key:     *k,
		nextSeq: invalidSequence,
		created: time.Now(),
		stream:  p.factory.New(*k),
	}
}

func (p *ConnectionPool) getConnection(k *Key) *connection {
	p.mu.RLock()
	conn := p.conns[*k]
	p.mu.RUnlock()
	if conn != nil {
		return conn
	}
	conn = p.newConnection(k)
	p.mu.Lock()
	if conn2 := p.conns[*k]; conn2 != nil {
		p.mu.Unlock()
		return conn2
	}
	p.conns[*k] = conn
	p.mu.Unlock()
	return conn
}

// Assemble reassembles the given TCP packet into its appropriate stream.
// Each Assemble call results in, in order:
//
//    zero or one calls to StreamFactory.New, creating a stream
//    zero or one calls to Reassembled on a single stream
//    zero or one calls to ReassemblyComplete on the same stream
func (a *Assembler) Assemble(t *TCP) {
	a.ret = a.ret[:0]
	conn := a.connPool.getConnection(&t.Key)
	conn.mu.Lock()
	conn.lastSeen = time.Now()
	if t.SYN {
		a.ret = append(a.ret, Reassembly{
			Bytes: t.Bytes,
			Seq:   t.Seq,
			Skip:  false,
			Start: true,
		})
		conn.nextSeq = t.Seq.Add(len(t.Bytes) + 1)
	} else if conn.nextSeq == invalidSequence || conn.nextSeq.Difference(t.Seq) > 0 {
		a.insertIntoConn(t, conn)
	} else {
		span := int(t.Seq.Difference(conn.nextSeq))
		if len(t.Bytes) > span {
			a.ret = append(a.ret, Reassembly{
				Bytes: t.Bytes[span:],
				Seq:   t.Seq + Sequence(span),
				Skip:  false,
				End:   t.RST || t.FIN,
			})
			conn.nextSeq = t.Seq.Add(len(t.Bytes))
		}
	}
	if len(a.ret) > 0 {
		a.sendToConnection(conn)
	}
	conn.mu.Unlock()
}

func (a *Assembler) sendToConnection(conn *connection) {
	a.addContiguous(conn)
	conn.stream.Reassembled(a.ret)
	if a.ret[len(a.ret)-1].End {
		a.closeConnection(conn)
	}
}

func (a *Assembler) addContiguous(conn *connection) {
	for conn.first != nil && conn.first.Seq == conn.nextSeq {
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

func (p *ConnectionPool) remove(conn *connection) {
	p.mu.Lock()
	delete(p.conns, conn.key)
	p.mu.Unlock()
}

func (a *Assembler) closeConnection(conn *connection) {
	conn.stream.ReassemblyComplete()
	a.connPool.remove(conn)
	for p := conn.first; p != nil; p = p.next {
		a.pc.replace(p)
	}
	conn.closed = true
}

func (conn *connection) traverseConn(t *TCP) (prev, current *page) {
	prev = conn.last
	for prev != nil && prev.Seq.Difference(t.Seq) < 0 {
		current = prev
		prev = current.prev
	}
	return
}

func (a *Assembler) insertIntoConn(t *TCP, conn *connection) {
	p, p2 := a.pagesFromTcp(t)
	prev, current := conn.traverseConn(t)
	// Maintain our doubly linked list
	if current == nil || conn.last == nil {
		conn.last = p2
	} else {
		p2.next = current
		current.prev = p2
	}
	if prev == nil || conn.first == nil {
		conn.first = p
	} else {
		p.prev = prev
		prev.next = p
	}
	conn.pages++
	if conn.pages >= a.maxBufferedPer || a.pc.used >= a.maxBuffered {
		a.addNextFromConn(conn, true)
	}
}

// pagesFromTcp creates a page (or set of pages) from a TCP packet.  Note that it
// should NEVER receive a SYN packet, as it doesn't handle sequences correctly.
// It returns the first and last page in its doubly-linked list of new pages.
func (a *Assembler) pagesFromTcp(t *TCP) (p, p2 *page) {
	first := a.pc.next()
	current := first
	for {
		length := min(len(t.Bytes), pageBytes)
		current.Bytes = current.buf[:length]
		copy(current.Bytes, t.Bytes)
		current.Seq = t.Seq
		t.Bytes = t.Bytes[length:]
		if len(t.Bytes) == 0 {
			break
		}
		t.Seq = t.Seq.Add(length)
		current.next = a.pc.next()
		current.next.prev = current
		current = current.next
	}
	current.End = t.RST || t.FIN
	return first, current
}

func (a *Assembler) addNextFromConn(conn *connection, skip bool) {
	conn.first.Skip = skip
	a.ret = append(a.ret, conn.first.Reassembly)
	conn.nextSeq = conn.first.Seq.Add(len(conn.first.Bytes))
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
