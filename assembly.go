package assembly

import (
	"fmt"
	"net"
	"time"
)

const seqRollover = 0xFFFFFFFF
const invalidSequence = -1

type Sequence int64

const shouldLog = false

func log(s string) {
	if shouldLog {
		fmt.Println(s)
	}
}

// difference defines an ordering for comparing TCP sequences that's safe for roll-overs.
// it returns:
//    > 0 : if t comes after s
//    < 0 : if t comes before s
//      0 : if t == s
func (s Sequence) Difference(t Sequence) int64 {
	if s > 0xFFFFFFFF-0xFFFFFFFF/4 && t < 0xFFFFFFFF/4 {
		t += 0xFFFFFFFF
	} else if t > 0xFFFFFFFF-0xFFFFFFFF/4 && s < 0xFFFFFFFF/4 {
		s += 0xFFFFFFFF
	}
	return int64(t - s)
}

func (s Sequence) Add(t int) Sequence {
	return (s + Sequence(t)) & 0xFFFFFFFF
}

type Reassembly struct {
	Bytes            []byte
	Seq              Sequence
	Skip, Start, End bool
}

const pageBytes = 2000

type page struct {
	Reassembly
	index      int
	prev, next *page
	created    time.Time
	buf        [pageBytes]byte
}

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

func (c *pageCache) grow() {
	pages := make([]page, c.pcSize)
	c.size += c.pcSize
	for i, _ := range pages {
		c.free = append(c.free, &pages[i])
	}
	c.pcSize *= 2
}

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

func (c *pageCache) replace(p *page) {
	c.used--
	c.free = append(c.free, p)
}

var zeros []byte = make([]byte, 12)

type Key struct {
	Version          byte // IP version, 4 or 6
	SrcIP, DstIP     [16]byte
	SrcPort, DstPort uint16
}

func (k *Key) Reset(sip, dip net.IP, sp, dp uint16) {
	if len(sip) != len(dip) {
		panic("IP lengths don't match")
	}
	switch len(sip) {
	case 4:
		k.Version = 4
		copy(k.SrcIP[:4], sip)
		copy(k.SrcIP[4:], zeros)
		copy(k.DstIP[:4], dip)
		copy(k.DstIP[4:], zeros)
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
  Close()
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
  conns := make([]*connection, 0, len(a.conns) / 10)
  for _, conn := range a.conns {
    if conn.first != nil && conn.first.created.Before(t) {
      conns = append(conns, conn)
    }
  }
  fmt.Println("Flushing", len(conns), "of", len(a.conns), "connections")
  closes := 0
  for _, conn := range conns {
    a.skipFlush(conn)
    if conn.closed {
      closes++
    }
  }
  fmt.Println("Flush completed in", time.Since(start), "closed", closes)
}

func NewAssembler(max, maxPer, pcSize int, factory StreamFactory) Assembler {
	return &assembler{
		ret:            make([]Reassembly, maxPer+1),
		pc:             newPageCache(pcSize),
		conns:          make(map[Key]*connection),
		maxBuffered:    max,
		maxBufferedPer: maxPer,
		factory:        factory,
	}
}

type connection struct {
  key Key
	pages       int
	first, last *page
	nextSeq     Sequence
	started     bool
	created     time.Time
	stream      Stream
  closed bool
}

type assembler struct {
	ret            []Reassembly
	pc             *pageCache
	maxBuffered    int
	maxBufferedPer int
	conns          map[Key]*connection
	factory        StreamFactory
}

func (a *assembler) newConnection(k *Key) *connection {
	return &connection{
    key: *k,
		nextSeq: invalidSequence,
		created: time.Now(),
		stream:  a.factory.New(*k),
	}
}

func (a *assembler) Assemble(t *TCP) {
	log("got")
	a.ret = a.ret[:0]
	conn := a.conns[t.Key]
	if conn == nil {
		log("  newconn")
		conn = a.newConnection(&t.Key)
		a.conns[t.Key] = conn
	}
	if t.SYN {
		log(" syn")
		a.ret = append(a.ret, Reassembly{
			Bytes: t.Bytes,
			Seq:   t.Seq,
			Skip:  false,
		})
		conn.nextSeq = t.Seq.Add(len(t.Bytes) + 1)
	} else if conn.nextSeq == invalidSequence || conn.nextSeq.Difference(t.Seq) > 0 {
		log(" outoforder")
		a.insertIntoConn(t, conn)
	} else {
		log(" inorder")
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
    log("  next")
    a.addNextFromConn(conn, false)
  }
  if !conn.started {
    conn.started = true
    a.ret[0].Start = true
  }
}

func (a *assembler) skipFlush(conn *connection) {
  a.ret = a.ret[:0]
  a.addNextFromConn(conn, true)
  a.sendToConnection(conn)
}

func (a *assembler) close(conn *connection) {
  conn.stream.Close()
  delete(a.conns, conn.key)
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
		log("  maxbuf")
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
