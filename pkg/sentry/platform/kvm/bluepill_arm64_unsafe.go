// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build arm64
// +build arm64

package kvm

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// fpsimdPtr returns a fpsimd64 for the given address.
//
//go:nosplit
func fpsimdPtr(addr *byte) *arch.FpsimdContext {
	return (*arch.FpsimdContext)(unsafe.Pointer(addr))
}

// dieArchSetup initializes the state for dieTrampoline.
//
// The arm64 dieTrampoline requires the vCPU to be set in R1, and the last PC
// to be in R0. The trampoline then simulates a call to dieHandler from the
// provided PC.
//
//go:nosplit
func (c *vCPU) dieArchSetup(context *arch.SignalContext64, guestRegs *userRegs, dumpExitReason bool) {
	// If the vCPU is in user mode, we set the stack to the stored stack
	// value in the vCPU itself. We don't want to unwind the user stack.
	if guestRegs.Regs.Pstate&ring0.PsrModeMask == ring0.UserFlagsSet {
		regs := c.CPU.Registers()
		context.Regs[0] = regs.Regs[0]
		context.Sp = regs.Sp
		context.Regs[29] = regs.Regs[29] // stack base address
	} else {
		context.Regs[0] = guestRegs.Regs.Pc
		context.Sp = guestRegs.Regs.Sp
		context.Regs[29] = guestRegs.Regs.Regs[29]
		context.Pstate = guestRegs.Regs.Pstate
	}
	if dumpExitReason {
		// Store the original instruction pointer in R9 and populates
		// registers R10-R14 with the vCPU's exit reason and associated
		// data from c.runData. To ensure this information is preserved
		// in a crash report, PC is set to an invalid address (0xabc).
		// This forces a memory fault immediately after a sigreturn,
		// triggering a crash report that includes the altered register
		// state, providing diagnostic details about why the vCPU
		// exited.
		context.Regs[9] = context.Pc
		context.Pc = 0xabc
		context.Regs[10] = uint64(c.runData.exitReason)
		context.Regs[11] = c.runData.data[0]
		context.Regs[12] = c.runData.data[1]
		context.Regs[13] = c.runData.data[2]
		context.Regs[14] = c.runData.data[3]
	} else {
		context.Regs[1] = uint64(uintptr(unsafe.Pointer(c)))
		context.Pc = uint64(dieTrampolineAddr)
	}
}

// getHypercallID returns hypercall ID.
//
// On Arm64, the MMIO address should be 64-bit aligned.
//
//go:nosplit
func getHypercallID(addr uintptr) int {
	if addr < arm64HypercallMMIOBase || addr >= (arm64HypercallMMIOBase+_AARCH64_HYPERCALL_MMIO_SIZE) {
		return _KVM_HYPERCALL_MAX
	} else {
		return int(((addr) - arm64HypercallMMIOBase) >> 3)
	}
}

// bluepillStopGuest is responsible for injecting sError.
//
//go:nosplit
func bluepillStopGuest(c *vCPU) {
	// vcpuSErrBounce is the event of system error for bouncing KVM.
	vcpuSErrBounce := &kvmVcpuEvents{
		exception: exception{
			sErrPending: 1,
		},
	}

	if errno := hostsyscall.RawSyscallErrno( // escapes: no.
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_VCPU_EVENTS,
		uintptr(unsafe.Pointer(vcpuSErrBounce))); errno != 0 {
		throw("bounce sErr injection failed")
	}
}

// bluepillSigBus is responsible for injecting sError to trigger sigbus.
//
//go:nosplit
func bluepillSigBus(c *vCPU) {
	// vcpuSErrNMI is the event of system error to trigger sigbus.
	vcpuSErrNMI := &kvmVcpuEvents{
		exception: exception{
			sErrPending: 1,
			sErrHasEsr:  1,
			sErrEsr:     _ESR_ELx_SERR_NMI,
		},
	}

	if !c.switchingToUser.Load() {
		// In the kernel mode (Sentry), Serrors are masked.
		// DABT (Data Abort) will force the Sentry returns back
		// to the host.
		bluepillExtDabt(c)
		return
	}

	// Host must support ARM64_HAS_RAS_EXTN.
	if errno := hostsyscall.RawSyscallErrno( // escapes: no.
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_VCPU_EVENTS,
		uintptr(unsafe.Pointer(vcpuSErrNMI))); errno != 0 {
		if errno == unix.EINVAL {
			throw("No ARM64_HAS_RAS_EXTN feature in host.")
		}
		throw("nmi sErr injection failed")
	}
}

// bluepillExtDabt is responsible for injecting external data abort.
//
//go:nosplit
func bluepillExtDabt(c *vCPU) {
	// vcpuExtDabt is the event of ext_dabt.
	vcpuExtDabt := &kvmVcpuEvents{
		exception: exception{
			extDabtPending: 1,
		},
	}

	if errno := hostsyscall.RawSyscallErrno( // escapes: no.
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_VCPU_EVENTS,
		uintptr(unsafe.Pointer(vcpuExtDabt))); errno != 0 {
		throw("ext_dabt injection failed")
	}
}

// bluepillHandleEnosys is responsible for handling enosys error.
//
//go:nosplit
func bluepillHandleEnosys(c *vCPU) {
	bluepillExtDabt(c)
}

// bluepillReadyStopGuest checks whether the current vCPU is ready for sError injection.
//
//go:nosplit
func bluepillReadyStopGuest(c *vCPU) bool {
	return true
}

// bluepillArchHandleExit checks architecture specific exitcode.
//
//go:nosplit
func bluepillArchHandleExit(c *vCPU, context unsafe.Pointer) {
	switch c.runData.exitReason {
	case _KVM_EXIT_ARM_NISV:
		bluepillExtDabt(c)
	default:
		c.dieAndDumpExitReason(bluepillArchContext(context))
	}
}
