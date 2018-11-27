// +build ignore

package pcap

//#include <pcap.h>
import "C"

import "syscall"

// keep gofmt happy
var _ = syscall.RawSockaddr{}

const errorBufferSize = C.PCAP_ERRBUF_SIZE

const (
	pcapErrorNotActivated = C.PCAP_ERROR_NOT_ACTIVATED
	pcapErrorActivated    = C.PCAP_ERROR_ACTIVATED
	pcapWarningPromisc    = C.PCAP_WARNING_PROMISC_NOTSUP
	pcapErrorNoSuchDevice = C.PCAP_ERROR_NO_SUCH_DEVICE
	pcapErrorDenied       = C.PCAP_ERROR_PERM_DENIED
	pcapErrorNotUp        = C.PCAP_ERROR_IFACE_NOT_UP
	pcapError             = C.PCAP_ERROR
	pcapWarning           = C.PCAP_WARNING
	pcapDIN               = C.PCAP_D_IN
	pcapDOUT              = C.PCAP_D_OUT
	pcapDINOUT            = C.PCAP_D_INOUT
	pcapNetmaskUnknown    = C.PCAP_NETMASK_UNKNOWN
)

type timeval C.struct_timeval
type pcapPkthdr C.struct_pcap_pkthdr
type pcapTPtr uintptr
type pcapBpfInstruction C.struct_bpf_insn
type pcapBpfProgram C.struct_bpf_program
type pcapStats C.struct_pcap_stat
type pcapCint C.int
type pcapIf C.struct_pcap_if

// +godefs map struct_sockaddr syscall.RawSockaddr
type pcapAddr C.struct_pcap_addr
