package assembly

import (
	logging "log"
	"time"
)

const shouldLog bool = false
func log(i ...interface{}) {
  if shouldLog {
		logging.Println(i...)
	}
}

const seqRollover = 0xFFFFFFFF
const invalidSequence = -1

type Sequence int64

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
	Bytes []byte
	Seq   Sequence
	Skip, Start, End bool
}

const pageBytes = 2000

type page struct {
	Reassembly
	index int
	next  *page
	buf   [pageBytes]byte
}

type pageCache struct {
	pages []page
	free  []int
}

func newPageCache(pcSize int) *pageCache {
	pc := &pageCache{
		pages: make([]page, pcSize),
		free:  make([]int, pcSize),
	}
	for i, _ := range pc.pages {
		pc.free[i] = i
	}
	return pc
}

func (c *pageCache) next() *page {
	if len(c.free) == 0 {
		return nil
	}
	i := len(c.free) - 1
	index := c.free[i]
	c.free = c.free[:i]
	p := &c.pages[index]
	p.next = nil
	p.Bytes = p.buf[:0]
	return p
}

func (c *pageCache) replace(p *page) {
	c.free = append(c.free, p.index)
}

type Key [1 + 16 + 16 + 2 + 2]byte

type TCP struct {
	Key           Key
	Seq           Sequence
	SYN, FIN, RST bool
	Bytes         []byte
}

type Assembler interface {
	Assemble(t *TCP) []Reassembly
}

func NewAssembler(max, maxPer, pcSize int) Assembler {
	return &assembler{
		ret:            make([]Reassembly, maxPer+1),
		pc:             newPageCache(pcSize),
		conns:          make(map[Key]*connection),
		maxBuffered:    max,
		maxBufferedPer: maxPer,
	}
}

type connection struct {
	pages   int
	p       *page
	nextSeq Sequence
	started bool
	first, last time.Time
}

type assembler struct {
	ret            []Reassembly
	pc             *pageCache
	buffered       int
	maxBuffered    int
	maxBufferedPer int
	conns          map[Key]*connection
}

func newConnection() *connection {
	now := time.Now()
	return &connection{
		nextSeq: invalidSequence,
		first: now,
	}
}

func (a *assembler) Assemble(t *TCP) []Reassembly {
	log("starting")
	a.ret = a.ret[:0]
	conn := a.conns[t.Key]
	if conn == nil {
		conn = newConnection()
		a.conns[t.Key] = conn
	}
	conn.last = time.Now()
	if t.SYN {
		log("  syn")
		a.ret = append(a.ret, Reassembly{
			Bytes: t.Bytes,
			Seq:   t.Seq,
			Skip:  false,
		})
		conn.nextSeq = t.Seq.Add(len(t.Bytes) + 1)
	} else if conn.nextSeq == invalidSequence || conn.nextSeq.Difference(t.Seq) > 0 {
		log("  gap")
		p := a.pageFromTcp(t)
		if p == nil {
			panic("page cache empty")
		}
		var last *page
		current := conn.p
		for current != nil && current.Seq.Difference(t.Seq) > 0 {
			last = current
			current = current.next
		}
		p.next = current
		if last == nil {
			conn.p = p
		} else {
			last.next = p
		}
		conn.pages++
		a.buffered++
		if conn.pages >= a.maxBufferedPer || a.buffered >= a.maxBuffered {
			log("  buffermax")
			a.addNextFromConn(conn, true)
		}
	} else {
		log("  nogap")
		span := int(t.Seq.Difference(conn.nextSeq))
		if len(t.Bytes) > span {
			a.ret = append(a.ret, Reassembly{
				Bytes: t.Bytes[span:],
				Seq:   t.Seq + Sequence(span),
				Skip:  false,
			})
			conn.nextSeq = t.Seq.Add(len(t.Bytes))
		}
	}
	log(" done1")
	if len(a.ret) > 0 {
		for conn.p != nil && conn.p.Seq == conn.nextSeq {
			log("  next")
			a.addNextFromConn(conn, false)
		}
		if !conn.started {
			conn.started = true
			a.ret[0].Start = true
		}
	}
	return a.ret
}

func (a *assembler) pageFromTcp(t *TCP) *page {
	// TODO(gconnell):  Split up tcp bytes by pageBytes
	p := a.pc.next()
	p.Bytes = p.buf[:len(t.Bytes)]
	copy(p.Bytes, t.Bytes)
	p.Seq = t.Seq
	p.End = t.RST || t.FIN
	return p
}

func (a *assembler) addNextFromConn(conn *connection, skip bool) {
	conn.p.Skip = skip
	a.ret = append(a.ret, conn.p.Reassembly)
	conn.nextSeq = conn.p.Seq.Add(len(conn.p.Bytes))
	log("  replacing")
	a.pc.replace(conn.p)
	conn.p = conn.p.next
}
