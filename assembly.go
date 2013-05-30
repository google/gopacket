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

func newPageCache(pcSize int) *pageCache {
	pc := &pageCache{
		free:   make([]*page, 0, pcSize),
		pcSize: pcSize,
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

type TCP struct {
	Key           Key
	Seq           Sequence
	SYN, FIN, RST bool
	Bytes         []byte
}

type Assembler interface {
	Assemble(t *TCP)
	Buffered() int
	FlushOlderThan(time.Time)
}

type Stream interface {
	Reassembled([]Reassembly)
	ReassemblyComplete()
}

type StreamFactory interface {
	New(k Key) Stream
}

func (a *assembler) Buffered() int {
	return a.pc.used
}

func (a *assembler) FlushOlderThan(t time.Time) {
	start := time.Now()
	fmt.Println("Flushing connections older than", t)
	a.connPool.mu.RLock()
	conns := make([]*connection, 0, len(a.connPool.conns))
	for _, conn := range a.connPool.conns {
		conns = append(conns, conn)
	}
	a.connPool.mu.RUnlock()
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

type ConnectionPool struct {
	conns   map[Key]*connection
	users   int
	mu      sync.RWMutex
	factory StreamFactory
}

func NewConnectionPool(factory StreamFactory) *ConnectionPool {
	return &ConnectionPool{
		conns:   make(map[Key]*connection),
		factory: factory,
	}
}

func NewAssembler(max, maxPer, pcSize int, pool *ConnectionPool) Assembler {
	pool.mu.Lock()
	pool.users++
	pool.mu.Unlock()
	return &assembler{
		ret:            make([]Reassembly, maxPer+1),
		pc:             newPageCache(pcSize),
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

type assembler struct {
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

func (a *assembler) Assemble(t *TCP) {
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

func (a *assembler) sendToConnection(conn *connection) {
	a.addContiguous(conn)
	conn.stream.Reassembled(a.ret)
	if a.ret[len(a.ret)-1].End {
		a.close(conn)
	}
}

func (a *assembler) addContiguous(conn *connection) {
	for conn.first != nil && conn.first.Seq == conn.nextSeq {
		a.addNextFromConn(conn, false)
	}
}

func (a *assembler) skipFlush(conn *connection) {
	if conn.first == nil {
		a.close(conn)
	} else {
		a.ret = a.ret[:0]
		a.addNextFromConn(conn, true)
		a.sendToConnection(conn)
	}
}

func (a *assembler) close(conn *connection) {
	conn.stream.ReassemblyComplete()
	a.connPool.mu.Lock()
	delete(a.connPool.conns, conn.key)
	a.connPool.mu.Unlock()
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

func (a *assembler) insertIntoConn(t *TCP, conn *connection) {
	p := a.pageFromTcp(t)
	prev, current := conn.traverseConn(t)
	// Maintain our doubly linked list
	if current == nil || conn.last == nil {
		conn.last = p
	} else {
		p.next = current
		current.prev = p
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

// pageFromTcp creates a page (or set of pages) from a TCP packet.  Note that it
// should NEVER receive a SYN packet, as it doesn't handle sequences correctly.
func (a *assembler) pageFromTcp(t *TCP) *page {
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
		current = current.next
	}
	current.End = t.RST || t.FIN
	return first
}

func (a *assembler) addNextFromConn(conn *connection, skip bool) {
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
