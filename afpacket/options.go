package afpacket

import (
	"fmt"
	"time"
)

// OptTPacketVersion is the version of TPacket to use.
// It can be passed into NewTPacket.
type OptTPacketVersion int

// String returns a string representation of the version, generally of the form V#.
func (t OptTPacketVersion) String() string {
	switch t {
	case TPacketVersion1:
		return "V1"
	case TPacketVersion2:
		return "V2"
	case TPacketVersion3:
		return "V3"
	case TPacketVersionHighestAvailable:
		return "HighestAvailable"
	}
	return "InvalidVersion"
}

const (
	// TPacketVersionHighestAvailable tells NewHandle to use the highest available version of tpacket the kernel has available.
	// This is the default, should a version number not be given in NewHandle's options.
	TPacketVersionHighestAvailable OptTPacketVersion = -1
	TPacketVersion1                OptTPacketVersion = 0
	TPacketVersion2                OptTPacketVersion = 1
	TPacketVersion3                OptTPacketVersion = 2
	tpacketVersionMax                                = 2
	tpacketVersionMin                                = -1
)

// OptInterface is the specific interface to bind to.
// It can be passed into NewTPacket.
type OptInterface string

// OptFrameSize is TPacket's tp_frame_size
// It can be passed into NewTPacket.
type OptFrameSize int

// OptBlockSize is TPacket's tp_block_size
// It can be passed into NewTPacket.
type OptBlockSize int

// OptNumBlocks is TPacket's tp_block_nr
// It can be passed into NewTPacket.
type OptNumBlocks int

// OptBlockTimeout is TPacket v3's tp_retire_blk_tov.  Note that it has only millisecond granularity, so must be >= 1 ms.
// It can be passed into NewTPacket.
type OptBlockTimeout time.Duration

const (
	DefaultFrameSize    = 4096                   // Default value for OptFrameSize.
	DefaultBlockSize    = DefaultFrameSize * 128 // Default value for OptBlockSize.
	DefaultNumBlocks    = 128                    // Default value for OptNumBlocks.
	DefaultBlockTimeout = 64 * time.Millisecond  // Default value for OptBlockTimeout.
)

type options struct {
	frameSize      int
	framesPerBlock int
	blockSize      int
	numBlocks      int
	blockTimeout   time.Duration
	version        OptTPacketVersion
	iface          string
}

var defaultOpts = options{
	frameSize:    DefaultFrameSize,
	blockSize:    DefaultBlockSize,
	numBlocks:    DefaultNumBlocks,
	blockTimeout: DefaultBlockTimeout,
	version:      TPacketVersionHighestAvailable,
}

func parseOptions(opts ...interface{}) (ret options, err error) {
	ret = defaultOpts
	for _, opt := range opts {
		switch v := opt.(type) {
		case OptFrameSize:
			ret.frameSize = int(v)
		case OptBlockSize:
			ret.blockSize = int(v)
		case OptNumBlocks:
			ret.numBlocks = int(v)
		case OptBlockTimeout:
			ret.blockTimeout = time.Duration(v)
		case OptTPacketVersion:
			ret.version = v
		case OptInterface:
			ret.iface = string(v)
		default:
			err = fmt.Errorf("unknown type in options")
			return
		}
	}
	if err = ret.check(); err != nil {
		return
	}
	ret.framesPerBlock = ret.blockSize / ret.frameSize
	return
}
func (o options) check() error {
	switch {
	case o.blockSize%pageSize != 0:
		return fmt.Errorf("block size %d must be divisible by page size %d", o.blockSize, pageSize)
	case o.blockSize%o.frameSize != 0:
		return fmt.Errorf("block size %d must be divisible by frame size %d", o.blockSize, o.frameSize)
	case o.numBlocks < 1:
		return fmt.Errorf("num blocks %d must be >= 1", o.numBlocks)
	case o.blockTimeout < time.Millisecond:
		return fmt.Errorf("block timeout %v must be > %v", o.blockTimeout, time.Millisecond)
	case o.version < tpacketVersionMin || o.version > tpacketVersionMax:
		return fmt.Errorf("tpacket version %v is invalid", o.version)
	}
	return nil
}
