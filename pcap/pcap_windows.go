// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcap

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	gosignature "github.com/NozomiNetworks/go-signature"
	"github.com/NozomiNetworks/gopacket-fork-nozomi"
	"github.com/NozomiNetworks/gopacket-fork-nozomi/layers"
	"golang.org/x/sys/windows"
)

var pcapLoaded = false

const npcapPath = "\\Npcap"
const wpcapDllName = "wpcap.dll"

//go:embed ca/DigiCertAut2021_2021-04-29.cer
var DigiCertAutCert []byte

const LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
const LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008

func hasDllAValidSignature(path string) error {
	return gosignature.CheckExeSignature(path, [][]byte{DigiCertAutCert})
}

func resolveNpcapDllPath(kernel32 windows.Handle) (string, error) {
	// We load SetDllDirectoryA, used to add a path to dll search path
	setDllDirectory, err := windows.GetProcAddress(kernel32, "SetDllDirectoryA")
	if err != nil {
		// we can't do anything since SetDllDirectoryA is missing - fall back to use first wpcap.dll we encounter
		return "", err
	}

	// We load GetSystemDirectoryA, used to retrieve the system32 folder path
	getSystemDirectory, err := windows.GetProcAddress(kernel32, "GetSystemDirectoryA")
	if err != nil {
		// we can't do anything since GetSystemDirectoryA is missing - fall back to use first wpcap.dll we encounter
		return "", err
	}

	const bufferSize = 4096
	buf := make([]byte, bufferSize)
	r, _, _ := syscall.SyscallN(getSystemDirectory, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 || int(r) > bufferSize-len(npcapPath)-1 {
		// Failed to get system32 folder, fallback to env variable
		system32Path := filepath.Join(os.Getenv("systemroot"), "System32", npcapPath)
		r = uintptr(len(system32Path))
		copy(buf, system32Path)
	} else {
		copy(buf[r:], npcapPath)
		r = uintptr(int(r) + len(npcapPath))
	}

	_, _, errN := syscall.SyscallN(setDllDirectory, uintptr(unsafe.Pointer(&buf[0])))
	// ignore errors here - we just fallback to load wpcap.dll from default locations
	if errN != windows.SEVERITY_SUCCESS {
		return "", fmt.Errorf("failed to set npcap path as search folder")
	}

	wpcapPath := filepath.Join(string(buf[:int(r)]), wpcapDllName)
	if os.Stat(wpcapPath); err != nil {
		return "", fmt.Errorf("%s doesn't exist in %s", wpcapDllName, wpcapPath)
	}

	err = hasDllAValidSignature(wpcapPath)
	if err != nil {
		return "", err
	}
	return wpcapPath, nil
}

func initLoadedDllPath(kernel32 windows.Handle) error {
	getModuleFileName, err := windows.GetProcAddress(kernel32, "GetModuleFileNameA")
	if err != nil {
		return err
	}
	buf := make([]byte, 4096)
	r, _, _ := syscall.SyscallN(getModuleFileName, uintptr(wpcapHandle), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 {
		// we can't get the filename of the loaded module in this case - just leave default of wpcap.dll
		return err
	}
	loadedDllPath := string(buf[:int(r)])
	return hasDllAValidSignature(loadedDllPath)
}

func mustLoad(fun string) (uintptr, error) {
	addr, err := windows.GetProcAddress(wpcapHandle, fun)
	if err != nil {
		return 0, fmt.Errorf("Couldn't load function %s from %s", fun, wpcapDllName)
	}
	return addr, nil
}

func mightLoad(fun string) uintptr {
	addr, err := windows.GetProcAddress(wpcapHandle, fun)
	if err != nil {
		return 0
	}
	return addr
}

func byteSliceToString(bval []byte) string {
	for i := range bval {
		if bval[i] == 0 {
			return string(bval[:i])
		}
	}
	return string(bval[:])
}

// bytePtrToString returns a string copied from pointer to a null terminated byte array
// WARNING: ONLY SAFE WITH IF r POINTS TO C MEMORY!
// govet will complain about this function for the reason stated above
func bytePtrToString(r uintptr) string {
	if r == 0 {
		return ""
	}
	bval := (*[1 << 30]byte)(unsafe.Pointer(r))
	return byteSliceToString(bval[:])
}

var wpcapHandle windows.Handle
var msvcrtHandle windows.Handle
var (
	callocPtr,
	pcapStrerrorPtr,
	pcapStatustostrPtr,
	pcapOpenLivePtr,
	pcapOpenOfflinePtr,
	pcapClosePtr,
	pcapGeterrPtr,
	pcapStatsPtr,
	pcapCompilePtr,
	pcapFreecodePtr,
	pcapLookupnetPtr,
	pcapOfflineFilterPtr,
	pcapSetfilterPtr,
	pcapListDatalinksPtr,
	pcapFreeDatalinksPtr,
	pcapDatalinkValToNamePtr,
	pcapDatalinkValToDescriptionPtr,
	pcapOpenDeadPtr,
	pcapNextExPtr,
	pcapDatalinkPtr,
	pcapSetDatalinkPtr,
	pcapDatalinkNameToValPtr,
	pcapLibVersionPtr,
	pcapFreealldevsPtr,
	pcapFindalldevsPtr,
	pcapSendpacketPtr,
	pcapSetdirectionPtr,
	pcapSnapshotPtr,
	pcapTstampTypeValToNamePtr,
	pcapTstampTypeNameToValPtr,
	pcapListTstampTypesPtr,
	pcapFreeTstampTypesPtr,
	pcapSetTstampTypePtr,
	pcapGetTstampPrecisionPtr,
	pcapSetTstampPrecisionPtr,
	pcapOpenOfflineWithTstampPrecisionPtr,
	pcapHOpenOfflineWithTstampPrecisionPtr,
	pcapActivatePtr,
	pcapCreatePtr,
	pcapSetSnaplenPtr,
	pcapSetPromiscPtr,
	pcapSetTimeoutPtr,
	pcapCanSetRfmonPtr,
	pcapSetRfmonPtr,
	pcapSetBufferSizePtr,
	pcapSetImmediateModePtr,
	pcapHopenOfflinePtr uintptr
)

func IsNpcapLoaded() bool {
	return pcapLoaded
}

func FreeNpcap() error {
	if pcapLoaded {
		_ = windows.FreeLibrary(msvcrtHandle)
		err := windows.FreeLibrary(wpcapHandle)
		if err != nil {
			return err
		}
		pcapLoaded = false
	}
	return nil
}

func isLoadLibraryExWithSearchFlagsSupported(kernel32 windows.Handle) bool {
	haveSearch, _ := windows.GetProcAddress(kernel32, "AddDllDirectory")
	return haveSearch != 0
}

// LoadNPCAP attempts to dynamically load the wpcap DLL and resolve necessary functions
func LoadNPCAP() error {
	if pcapLoaded {
		return nil
	}

	kernel32, err := loadKernel32()
	if err != nil {
		return err
	}
	defer windows.FreeLibrary(kernel32)

	npcapDllPath, err := resolveNpcapDllPath(kernel32)
	if isLoadLibraryExWithSearchFlagsSupported(kernel32) {
		// if AddDllDirectory is present, we can use LOAD_LIBRARY_* stuff with LoadLibraryEx to avoid wpcap.dll hijacking
		// see: https://msdn.microsoft.com/en-us/library/ff919712%28VS.85%29.aspx
		if err == nil {
			wpcapHandle, err = windows.LoadLibraryEx(npcapDllPath, 0, LOAD_WITH_ALTERED_SEARCH_PATH)
		} else {
			wpcapHandle, err = windows.LoadLibraryEx(wpcapDllName, 0, LOAD_LIBRARY_SEARCH_SYSTEM32)
		}

		if err != nil {
			return fmt.Errorf("couldn't load %s", wpcapDllName)
		}
	} else {
		// otherwise fall back to load it with the unsafe search cause by SetDllDirectory
		// This is unsafe, but required on windows 7 without KB2533623
		wpcapHandle, err = windows.LoadLibrary(wpcapDllName)
		if err != nil {
			return fmt.Errorf("couldn't load %s", wpcapDllName)
		}
	}
	err = initLoadedDllPath(kernel32)
	if err != nil {
		defer windows.FreeLibrary(wpcapHandle)
		return err
	}
	err = loadMsvcrt(kernel32)
	if err != nil {
		defer windows.FreeLibrary(wpcapHandle)
		return err
	}

	//libpcap <1.5 does not have pcap_set_immediate_mode
	err = linkWpcapMethods()
	if err != nil {
		defer windows.FreeLibrary(wpcapHandle)
		defer windows.FreeLibrary(msvcrtHandle)
		return err
	}

	pcapLoaded = true
	return nil
}

func loadKernel32() (windows.Handle, error) {
	// no need to digital signature check, if you hijack "kernel32.dll" the whole system is already compromised
	kernel32, err := windows.LoadLibraryEx("kernel32.dll", 0, LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		// kernel32.dll must be present, if it fails means that LoadLibraryEx is not supported
		// so we try to load it in an unsafe way, the risk is to load another kernel32.dll in a different path,
		// but this is unlikely, and if possible all software on the machine are potentially vulnerable
		kernel32, err = windows.LoadLibrary("kernel32.dll")
		if err != nil {
			return kernel32, fmt.Errorf("couldn't load kernel32.dll")
		}
	}
	return kernel32, nil
}

func loadMsvcrt(kernel32 windows.Handle) (err error) {
	// this requires MS VC++ runtime
	if isLoadLibraryExWithSearchFlagsSupported(kernel32) {
		msvcrtHandle, err = windows.LoadLibraryEx("msvcrt.dll", 0, LOAD_LIBRARY_SEARCH_SYSTEM32)
	} else {
		//load in an unsafe way. this is case is still vulnerable
		msvcrtHandle, err = windows.LoadLibrary("msvcrt.dll")
	}

	if err != nil {
		return fmt.Errorf("couldn't load msvcrt.dll")
	}
	callocPtr, err = windows.GetProcAddress(msvcrtHandle, "calloc")
	if err != nil {
		defer windows.FreeLibrary(msvcrtHandle)
		return fmt.Errorf("couldn't get calloc function")
	}
	return nil
}

func linkWpcapMethods() (err error) {
	if pcapStrerrorPtr, err = mustLoad("pcap_strerror"); err != nil {
		return err
	}
	// pcap_statustostr not available on winpcap
	pcapStatustostrPtr = mightLoad("pcap_statustostr")

	if pcapOpenLivePtr, err = mustLoad("pcap_open_live"); err != nil {
		return err
	}
	if pcapOpenOfflinePtr, err = mustLoad("pcap_open_offline"); err != nil {
		return err
	}
	if pcapClosePtr, err = mustLoad("pcap_close"); err != nil {
		return err
	}
	if pcapGeterrPtr, err = mustLoad("pcap_geterr"); err != nil {
		return err
	}
	if pcapStatsPtr, err = mustLoad("pcap_stats"); err != nil {
		return err
	}
	if pcapCompilePtr, err = mustLoad("pcap_compile"); err != nil {
		return err
	}
	if pcapFreecodePtr, err = mustLoad("pcap_freecode"); err != nil {
		return err
	}
	if pcapLookupnetPtr, err = mustLoad("pcap_lookupnet"); err != nil {
		return err
	}
	if pcapOfflineFilterPtr, err = mustLoad("pcap_offline_filter"); err != nil {
		return err
	}
	if pcapSetfilterPtr, err = mustLoad("pcap_setfilter"); err != nil {
		return err
	}
	if pcapListDatalinksPtr, err = mustLoad("pcap_list_datalinks"); err != nil {
		return err
	}
	if pcapFreeDatalinksPtr, err = mustLoad("pcap_free_datalinks"); err != nil {
		return err
	}
	if pcapDatalinkValToNamePtr, err = mustLoad("pcap_datalink_val_to_name"); err != nil {
		return err
	}
	if pcapDatalinkValToDescriptionPtr, err = mustLoad("pcap_datalink_val_to_description"); err != nil {
		return err
	}
	if pcapOpenDeadPtr, err = mustLoad("pcap_open_dead"); err != nil {
		return err
	}
	if pcapNextExPtr, err = mustLoad("pcap_next_ex"); err != nil {
		return err
	}
	if pcapDatalinkPtr, err = mustLoad("pcap_datalink"); err != nil {
		return err
	}
	if pcapSetDatalinkPtr, err = mustLoad("pcap_set_datalink"); err != nil {
		return err
	}
	if pcapDatalinkNameToValPtr, err = mustLoad("pcap_datalink_name_to_val"); err != nil {
		return err
	}
	if pcapLibVersionPtr, err = mustLoad("pcap_lib_version"); err != nil {
		return err
	}
	if pcapFreealldevsPtr, err = mustLoad("pcap_freealldevs"); err != nil {
		return err
	}
	if pcapFindalldevsPtr, err = mustLoad("pcap_findalldevs"); err != nil {
		return err
	}
	if pcapSendpacketPtr, err = mustLoad("pcap_sendpacket"); err != nil {
		return err
	}
	if pcapSetdirectionPtr, err = mustLoad("pcap_setdirection"); err != nil {
		return err
	}
	if pcapSnapshotPtr, err = mustLoad("pcap_snapshot"); err != nil {
		return err
	}

	//libpcap <1.2 doesn't have pcap_*_tstamp_* functions
	pcapTstampTypeValToNamePtr = mightLoad("pcap_tstamp_type_val_to_name")
	pcapTstampTypeNameToValPtr = mightLoad("pcap_tstamp_type_name_to_val")
	pcapListTstampTypesPtr = mightLoad("pcap_list_tstamp_types")
	pcapFreeTstampTypesPtr = mightLoad("pcap_free_tstamp_types")
	pcapSetTstampTypePtr = mightLoad("pcap_set_tstamp_type")
	pcapGetTstampPrecisionPtr = mightLoad("pcap_get_tstamp_precision")
	pcapSetTstampPrecisionPtr = mightLoad("pcap_set_tstamp_precision")

	pcapOpenOfflineWithTstampPrecisionPtr = mightLoad("pcap_open_offline_with_tstamp_precision")
	pcapHOpenOfflineWithTstampPrecisionPtr = mightLoad("pcap_hopen_offline_with_tstamp_precision")
	if pcapActivatePtr, err = mustLoad("pcap_activate"); err != nil {
		return err
	}
	if pcapCreatePtr, err = mustLoad("pcap_create"); err != nil {
		return err
	}
	if pcapSetSnaplenPtr, err = mustLoad("pcap_set_snaplen"); err != nil {
		return err
	}
	if pcapSetPromiscPtr, err = mustLoad("pcap_set_promisc"); err != nil {
		return err
	}
	if pcapSetTimeoutPtr, err = mustLoad("pcap_set_timeout"); err != nil {
		return err
	}

	//winpcap does not support rfmon
	pcapCanSetRfmonPtr = mightLoad("pcap_can_set_rfmon")
	pcapSetRfmonPtr = mightLoad("pcap_set_rfmon")
	if pcapSetBufferSizePtr, err = mustLoad("pcap_set_buffer_size"); err != nil {
		return err
	}

	pcapSetImmediateModePtr = mightLoad("pcap_set_immediate_mode")
	if pcapHopenOfflinePtr, err = mustLoad("pcap_hopen_offline"); err != nil {
		return err
	}
	return nil
}

func (h *pcapPkthdr) getSec() int64 {
	return int64(h.Ts.Sec)
}

func (h *pcapPkthdr) getUsec() int64 {
	return int64(h.Ts.Usec)
}

func (h *pcapPkthdr) getLen() int {
	return int(h.Len)
}

func (h *pcapPkthdr) getCaplen() int {
	return int(h.Caplen)
}

func statusError(status pcapCint) error {
	var ret uintptr
	if pcapStatustostrPtr == 0 {
		ret, _, _ = syscall.SyscallN(pcapStrerrorPtr, uintptr(status))
	} else {
		ret, _, _ = syscall.SyscallN(pcapStatustostrPtr, uintptr(status))
	}
	return errors.New(bytePtrToString(ret))
}

func pcapGetTstampPrecision(cptr pcapTPtr) int {
	if pcapGetTstampPrecisionPtr == 0 {
		return pcapTstampPrecisionMicro
	}
	ret, _, _ := syscall.SyscallN(pcapGetTstampPrecisionPtr, uintptr(cptr))
	return int(pcapCint(ret))
}

func pcapSetTstampPrecision(cptr pcapTPtr, precision int) error {
	if pcapSetTstampPrecisionPtr == 0 {
		return errors.New("Not supported")
	}
	ret, _, _ := syscall.SyscallN(pcapSetTstampPrecisionPtr, uintptr(cptr), uintptr(precision))
	if pcapCint(ret) < 0 {
		return errors.New("Not supported")
	}
	return nil
}

func pcapOpenLive(device string, snaplen int, pro int, timeout int) (*Handle, error) {
	err := LoadNPCAP()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, errorBufferSize)
	dev, err := syscall.BytePtrFromString(device)
	if err != nil {
		return nil, err
	}

	cptr, _, _ := syscall.SyscallN(pcapOpenLivePtr, uintptr(unsafe.Pointer(dev)), uintptr(snaplen), uintptr(pro), uintptr(timeout), uintptr(unsafe.Pointer(&buf[0])))

	if cptr == 0 {
		return nil, errors.New(byteSliceToString(buf))
	}
	return &Handle{cptr: pcapTPtr(cptr)}, nil
}

func openOffline(file string) (handle *Handle, err error) {
	err = LoadNPCAP()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, errorBufferSize)
	f, err := syscall.BytePtrFromString(file)
	if err != nil {
		return nil, err
	}

	var cptr uintptr
	if pcapOpenOfflineWithTstampPrecisionPtr == 0 {
		cptr, _, _ = syscall.SyscallN(pcapOpenOfflinePtr, uintptr(unsafe.Pointer(f)), uintptr(unsafe.Pointer(&buf[0])))
	} else {
		cptr, _, _ = syscall.SyscallN(pcapOpenOfflineWithTstampPrecisionPtr, uintptr(unsafe.Pointer(f)), uintptr(pcapTstampPrecisionNano), uintptr(unsafe.Pointer(&buf[0])))
	}

	if cptr == 0 {
		return nil, errors.New(byteSliceToString(buf))
	}

	h := &Handle{cptr: pcapTPtr(cptr)}
	return h, nil
}

func (p *Handle) pcapClose() {
	if p.cptr != 0 {
		_, _, _ = syscall.SyscallN(pcapClosePtr, uintptr(p.cptr))
	}
	p.cptr = 0
}

func (p *Handle) pcapGeterr() error {
	ret, _, _ := syscall.SyscallN(pcapGeterrPtr, uintptr(p.cptr))
	return errors.New(bytePtrToString(ret))
}

func (p *Handle) pcapStats() (*Stats, error) {
	var cstats pcapStats
	ret, _, _ := syscall.SyscallN(pcapStatsPtr, uintptr(p.cptr), uintptr(unsafe.Pointer(&cstats)))
	if pcapCint(ret) < 0 {
		return nil, p.pcapGeterr()
	}
	return &Stats{
		PacketsReceived:  int(cstats.Recv),
		PacketsDropped:   int(cstats.Drop),
		PacketsIfDropped: int(cstats.Ifdrop),
	}, nil
}

// for libpcap < 1.8 pcap_compile is NOT thread-safe, so protect it.
var pcapCompileMu sync.Mutex

func (p *Handle) pcapCompile(expr string, maskp uint32) (pcapBpfProgram, error) {
	var bpf pcapBpfProgram
	cexpr, err := syscall.BytePtrFromString(expr)
	if err != nil {
		return pcapBpfProgram{}, err
	}
	pcapCompileMu.Lock()
	defer pcapCompileMu.Unlock()
	res, _, _ := syscall.SyscallN(pcapCompilePtr, uintptr(p.cptr), uintptr(unsafe.Pointer(&bpf)), uintptr(unsafe.Pointer(cexpr)), uintptr(1), uintptr(maskp))
	if pcapCint(res) < 0 {
		return bpf, p.pcapGeterr()
	}
	return bpf, nil
}

func (p pcapBpfProgram) free() {
	_, _, _ = syscall.SyscallN(pcapFreecodePtr, uintptr(unsafe.Pointer(&p)))
}

func (p pcapBpfProgram) toBPFInstruction() []BPFInstruction {
	bpfInsn := (*[bpfInstructionBufferSize]pcapBpfInstruction)(unsafe.Pointer(p.Insns))[0:p.Len:p.Len]
	bpfInstruction := make([]BPFInstruction, len(bpfInsn), len(bpfInsn))

	for i, v := range bpfInsn {
		bpfInstruction[i].Code = v.Code
		bpfInstruction[i].Jt = v.Jt
		bpfInstruction[i].Jf = v.Jf
		bpfInstruction[i].K = v.K
	}
	return bpfInstruction
}

func pcapBpfProgramFromInstructions(bpfInstructions []BPFInstruction) pcapBpfProgram {
	var bpf pcapBpfProgram
	bpf.Len = uint32(len(bpfInstructions))
	cbpfInsns, _, _ := syscall.SyscallN(callocPtr, uintptr(len(bpfInstructions)), uintptr(unsafe.Sizeof(bpfInstructions[0])))
	gbpfInsns := (*[bpfInstructionBufferSize]pcapBpfInstruction)(unsafe.Pointer(cbpfInsns))

	for i, v := range bpfInstructions {
		gbpfInsns[i].Code = v.Code
		gbpfInsns[i].Jt = v.Jt
		gbpfInsns[i].Jf = v.Jf
		gbpfInsns[i].K = v.K
	}

	bpf.Insns = (*pcapBpfInstruction)(unsafe.Pointer(cbpfInsns))
	return bpf
}

func pcapLookupnet(device string) (netp, maskp uint32, err error) {
	err = LoadNPCAP()
	if err != nil {
		return 0, 0, err
	}

	buf := make([]byte, errorBufferSize)
	dev, err := syscall.BytePtrFromString(device)
	if err != nil {
		return 0, 0, err
	}
	e, _, _ := syscall.SyscallN(pcapLookupnetPtr, uintptr(unsafe.Pointer(dev)), uintptr(unsafe.Pointer(&netp)), uintptr(unsafe.Pointer(&maskp)), uintptr(unsafe.Pointer(&buf[0])))
	if pcapCint(e) < 0 {
		return 0, 0, errors.New(byteSliceToString(buf))
	}
	return
}

func (b *BPF) pcapOfflineFilter(ci gopacket.CaptureInfo, data []byte) bool {
	var hdr pcapPkthdr
	hdr.Ts.Sec = int32(ci.Timestamp.Unix())
	hdr.Ts.Usec = int32(ci.Timestamp.Nanosecond() / 1000)
	hdr.Caplen = uint32(len(data)) // Trust actual length over ci.Length.
	hdr.Len = uint32(ci.Length)
	e, _, _ := syscall.SyscallN(pcapOfflineFilterPtr, uintptr(unsafe.Pointer(&b.bpf.bpf)), uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])))
	return e != 0
}

func (p *Handle) pcapSetfilter(bpf pcapBpfProgram) error {
	e, _, _ := syscall.SyscallN(pcapSetfilterPtr, uintptr(p.cptr), uintptr(unsafe.Pointer(&bpf)))
	if pcapCint(e) < 0 {
		return p.pcapGeterr()
	}
	return nil
}

func (p *Handle) pcapListDatalinks() (datalinks []Datalink, err error) {
	var dltbuf *pcapCint
	ret, _, _ := syscall.SyscallN(pcapListDatalinksPtr, uintptr(p.cptr), uintptr(unsafe.Pointer(&dltbuf)))

	n := int(pcapCint(ret))

	if n < 0 {
		return nil, p.pcapGeterr()
	}
	defer syscall.SyscallN(pcapFreeDatalinksPtr, uintptr(unsafe.Pointer(dltbuf)))

	datalinks = make([]Datalink, n)

	dltArray := (*[1 << 28]pcapCint)(unsafe.Pointer(dltbuf))

	for i := 0; i < n; i++ {
		datalinks[i].Name = pcapDatalinkValToName(int((*dltArray)[i]))
		datalinks[i].Description = pcapDatalinkValToDescription(int((*dltArray)[i]))
	}

	return datalinks, nil
}

func pcapOpenDead(linkType layers.LinkType, captureLength int) (*Handle, error) {
	err := LoadNPCAP()
	if err != nil {
		return nil, err
	}

	cptr, _, _ := syscall.SyscallN(pcapOpenDeadPtr, uintptr(linkType), uintptr(captureLength))
	if cptr == 0 {
		return nil, errors.New("error opening dead capture")
	}

	return &Handle{cptr: pcapTPtr(cptr)}, nil
}

func (p *Handle) pcapNextPacketEx() NextError {
	r, _, _ := syscall.SyscallN(pcapNextExPtr, uintptr(p.cptr), uintptr(unsafe.Pointer(&p.pkthdr)), uintptr(unsafe.Pointer(&p.bufptr)))
	ret := pcapCint(r)
	// According to https://github.com/the-tcpdump-group/libpcap/blob/1131a7c26c6f4d4772e4a2beeaf7212f4dea74ac/pcap.c#L398-L406 ,
	// the return value of pcap_next_ex could be greater than 1 for success.
	// Let's just make it 1 if it comes bigger than 1.
	if ret > 1 {
		ret = 1
	}
	return NextError(ret)
}

func (p *Handle) pcapDatalink() layers.LinkType {
	ret, _, _ := syscall.SyscallN(pcapDatalinkPtr, uintptr(p.cptr))
	return layers.LinkType(ret)
}

func (p *Handle) pcapSetDatalink(dlt layers.LinkType) error {
	ret, _, _ := syscall.SyscallN(pcapSetDatalinkPtr, 2, uintptr(p.cptr), uintptr(dlt))
	if pcapCint(ret) < 0 {
		return p.pcapGeterr()
	}
	return nil
}

func pcapDatalinkValToName(dlt int) string {
	_ = LoadNPCAP()
	ret, _, _ := syscall.SyscallN(pcapDatalinkValToNamePtr, uintptr(dlt))
	return bytePtrToString(ret)
}

func pcapDatalinkValToDescription(dlt int) string {
	_ = LoadNPCAP()
	ret, _, _ := syscall.SyscallN(pcapDatalinkValToDescriptionPtr, uintptr(dlt))
	return bytePtrToString(ret)
}

func pcapDatalinkNameToVal(name string) int {
	_ = LoadNPCAP()
	cptr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0
	}
	ret, _, _ := syscall.SyscallN(pcapDatalinkNameToValPtr, uintptr(unsafe.Pointer(cptr)))
	return int(pcapCint(ret))
}

func pcapLibVersion() string {
	_ = LoadNPCAP()
	ret, _, _ := syscall.SyscallN(pcapLibVersionPtr)
	return bytePtrToString(ret)
}

func (p *Handle) isOpen() bool {
	return p.cptr != 0
}

type pcapDevices struct {
	all, cur *pcapIf
}

func (p pcapDevices) free() {
	syscall.SyscallN(pcapFreealldevsPtr, uintptr(unsafe.Pointer(p.all)))
}

func (p *pcapDevices) next() bool {
	if p.cur == nil {
		p.cur = p.all
		if p.cur == nil {
			return false
		}
		return true
	}
	if p.cur.Next == nil {
		return false
	}
	p.cur = p.cur.Next
	return true
}

func (p pcapDevices) name() string {
	return bytePtrToString(uintptr(unsafe.Pointer(p.cur.Name)))
}

func (p pcapDevices) description() string {
	return bytePtrToString(uintptr(unsafe.Pointer(p.cur.Description)))
}

func (p pcapDevices) flags() uint32 {
	return p.cur.Flags
}

type pcapAddresses struct {
	all, cur *pcapAddr
}

func (p *pcapAddresses) next() bool {
	if p.cur == nil {
		p.cur = p.all
		if p.cur == nil {
			return false
		}
		return true
	}
	if p.cur.Next == nil {
		return false
	}
	p.cur = p.cur.Next
	return true
}

func (p pcapAddresses) addr() *syscall.RawSockaddr {
	return p.cur.Addr
}

func (p pcapAddresses) netmask() *syscall.RawSockaddr {
	return p.cur.Netmask
}

func (p pcapAddresses) broadaddr() *syscall.RawSockaddr {
	return p.cur.Broadaddr
}

func (p pcapAddresses) dstaddr() *syscall.RawSockaddr {
	return p.cur.Dstaddr
}

func (p pcapDevices) addresses() pcapAddresses {
	return pcapAddresses{all: p.cur.Addresses}
}

func pcapFindAllDevs() (pcapDevices, error) {
	var alldevsp pcapDevices
	err := LoadNPCAP()
	if err != nil {
		return alldevsp, err
	}

	buf := make([]byte, errorBufferSize)

	ret, _, _ := syscall.SyscallN(pcapFindalldevsPtr, uintptr(unsafe.Pointer(&alldevsp.all)), uintptr(unsafe.Pointer(&buf[0])))

	if pcapCint(ret) < 0 {
		return pcapDevices{}, errors.New(byteSliceToString(buf))
	}
	return alldevsp, nil
}

func (p *Handle) pcapSendpacket(data []byte) error {
	ret, _, _ := syscall.SyscallN(pcapSendpacketPtr, uintptr(p.cptr), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
	if pcapCint(ret) < 0 {
		return p.pcapGeterr()
	}
	return nil
}

func (p *Handle) pcapSetdirection(direction Direction) error {
	status, _, _ := syscall.SyscallN(pcapSetdirectionPtr, 2, uintptr(p.cptr), uintptr(direction))
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *Handle) pcapSnapshot() int {
	ret, _, _ := syscall.SyscallN(pcapSnapshotPtr, uintptr(p.cptr))
	return int(pcapCint(ret))
}

func (t TimestampSource) pcapTstampTypeValToName() string {
	err := LoadNPCAP()
	if err != nil {
		return err.Error()
	}

	//libpcap <1.2 doesn't have pcap_*_tstamp_* functions
	if pcapTstampTypeValToNamePtr == 0 {
		return "pcap timestamp types not supported"
	}
	ret, _, _ := syscall.SyscallN(pcapTstampTypeValToNamePtr, 1, uintptr(t))
	return bytePtrToString(ret)
}

func pcapTstampTypeNameToVal(s string) (TimestampSource, error) {
	err := LoadNPCAP()
	if err != nil {
		return 0, err
	}

	//libpcap <1.2 doesn't have pcap_*_tstamp_* functions
	if pcapTstampTypeNameToValPtr == 0 {
		return 0, statusError(pcapCint(pcapError))
	}
	cs, err := syscall.BytePtrFromString(s)
	if err != nil {
		return 0, err
	}
	ret, _, _ := syscall.SyscallN(pcapTstampTypeNameToValPtr, 1, uintptr(unsafe.Pointer(cs)))
	t := pcapCint(ret)
	if t < 0 {
		return 0, statusError(pcapCint(t))
	}
	return TimestampSource(t), nil
}

func (p *InactiveHandle) pcapGeterr() error {
	ret, _, _ := syscall.SyscallN(pcapGeterrPtr, uintptr(p.cptr))
	return errors.New(bytePtrToString(ret))
}

func (p *InactiveHandle) pcapActivate() (*Handle, activateError) {
	r, _, _ := syscall.SyscallN(pcapActivatePtr, uintptr(p.cptr))
	ret := activateError(pcapCint(r))
	if ret != aeNoError {
		return nil, ret
	}
	h := &Handle{
		cptr: p.cptr,
	}
	p.cptr = 0
	return h, ret
}

func (p *InactiveHandle) pcapClose() {
	if p.cptr != 0 {
		_, _, _ = syscall.SyscallN(pcapClosePtr, uintptr(p.cptr))
	}
	p.cptr = 0
}

func pcapCreate(device string) (*InactiveHandle, error) {
	err := LoadNPCAP()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, errorBufferSize)
	dev, err := syscall.BytePtrFromString(device)
	if err != nil {
		return nil, err
	}
	cptr, _, _ := syscall.SyscallN(pcapCreatePtr, uintptr(unsafe.Pointer(dev)), uintptr(unsafe.Pointer(&buf[0])))
	if cptr == 0 {
		return nil, errors.New(byteSliceToString(buf))
	}
	return &InactiveHandle{cptr: pcapTPtr(cptr)}, nil
}

func (p *InactiveHandle) pcapSetSnaplen(snaplen int) error {
	status, _, _ := syscall.SyscallN(pcapSetSnaplenPtr, uintptr(p.cptr), uintptr(snaplen))
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *InactiveHandle) pcapSetPromisc(promisc bool) error {
	var pro uintptr
	if promisc {
		pro = 1
	}
	status, _, _ := syscall.SyscallN(pcapSetPromiscPtr, uintptr(p.cptr), pro)
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *InactiveHandle) pcapSetTimeout(timeout time.Duration) error {
	status, _, _ := syscall.SyscallN(pcapSetTimeoutPtr, uintptr(p.cptr), uintptr(timeoutMillis(timeout)))

	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *InactiveHandle) pcapListTstampTypes() (out []TimestampSource) {
	//libpcap <1.2 doesn't have pcap_*_tstamp_* functions
	if pcapListTstampTypesPtr == 0 {
		return
	}
	var types *pcapCint
	ret, _, _ := syscall.SyscallN(pcapListTstampTypesPtr, uintptr(p.cptr), uintptr(unsafe.Pointer(&types)))
	n := int(pcapCint(ret))
	if n < 0 {
		return // public interface doesn't have error :(
	}
	defer syscall.SyscallN(pcapFreeTstampTypesPtr, 1, uintptr(unsafe.Pointer(types)))
	typesArray := (*[1 << 28]pcapCint)(unsafe.Pointer(types))
	for i := 0; i < n; i++ {
		out = append(out, TimestampSource((*typesArray)[i]))
	}
	return
}

func (p *InactiveHandle) pcapSetTstampType(t TimestampSource) error {
	//libpcap <1.2 doesn't have pcap_*_tstamp_* functions
	if pcapSetTstampTypePtr == 0 {
		return statusError(pcapError)
	}
	status, _, _ := syscall.SyscallN(pcapSetTstampTypePtr, uintptr(p.cptr), uintptr(t))
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *InactiveHandle) pcapSetRfmon(monitor bool) error {
	//winpcap does not support rfmon
	if pcapCanSetRfmonPtr == 0 {
		return CannotSetRFMon
	}
	var mon uintptr
	if monitor {
		mon = 1
	}
	canset, _, _ := syscall.SyscallN(pcapCanSetRfmonPtr, uintptr(p.cptr))
	switch canset {
	case 0:
		return CannotSetRFMon
	case 1:
		// success
	default:
		return statusError(pcapCint(canset))
	}
	status, _, _ := syscall.SyscallN(pcapSetRfmonPtr, uintptr(p.cptr), mon)
	if status != 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *InactiveHandle) pcapSetBufferSize(bufferSize int) error {
	status, _, _ := syscall.SyscallN(pcapSetBufferSizePtr, uintptr(p.cptr), uintptr(bufferSize))
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *InactiveHandle) pcapSetImmediateMode(mode bool) error {
	//libpcap <1.5 does not have pcap_set_immediate_mode
	if pcapSetImmediateModePtr == 0 {
		return statusError(pcapError)
	}
	var md uintptr
	if mode {
		md = 1
	}
	status, _, _ := syscall.SyscallN(pcapSetImmediateModePtr, uintptr(p.cptr), md)
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *Handle) setNonBlocking() error {
	// do nothing
	return nil
}

// waitForPacket waits for a packet or for the timeout to expire.
func (p *Handle) waitForPacket() {
	// can't use select() so instead just switch goroutines
	runtime.Gosched()
}

// openOfflineFile returns contents of input file as a *Handle.
func openOfflineFile(file *os.File) (handle *Handle, err error) {
	err = LoadNPCAP()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, errorBufferSize)
	cf := file.Fd()

	var cptr uintptr
	if pcapOpenOfflineWithTstampPrecisionPtr == 0 {
		cptr, _, _ = syscall.SyscallN(pcapHopenOfflinePtr, cf, uintptr(unsafe.Pointer(&buf[0])))
	} else {
		cptr, _, _ = syscall.SyscallN(pcapHOpenOfflineWithTstampPrecisionPtr, cf, uintptr(pcapTstampPrecisionNano), uintptr(unsafe.Pointer(&buf[0])))
	}

	if cptr == 0 {
		return nil, errors.New(byteSliceToString(buf))
	}
	return &Handle{cptr: pcapTPtr(cptr)}, nil
}
