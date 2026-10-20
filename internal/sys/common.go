package sys

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

var commonAttrsFeatures = internal.FeatureMatrix[Cmd]{BPF_COMMON_ATTRS: {
	Name: "BPF syscall common attributes",
	Fn: func() error {
		if runtime.GOOS != "linux" {
			return internal.ErrNotSupportedOnOS
		}

		// A supported kernel tries to copy the common attributes before
		// validating the program, and faults on the NULL pointer.
		var attr ProgLoadAttr
		fd, _, errno := unix.Syscall6(unix.SYS_BPF, uintptr(BPF_PROG_LOAD|BPF_COMMON_ATTRS),
			uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0, unsafe.Sizeof(CommonAttr{}), 0)
		runtime.KeepAlive(&attr)
		switch errno {
		case unix.EFAULT:
			return nil
		case unix.EINVAL:
			return internal.ErrNotSupported
		case 0:
			unix.Close(int(fd))
			return fmt.Errorf("common attributes probe unexpectedly succeeded")
		default:
			return wrappedErrno{errno}
		}
	},
}}

// HaveCommonAttrs reports whether the kernel accepts common syscall attributes.
func HaveCommonAttrs() error {
	return commonAttrsFeatures.Result(BPF_COMMON_ATTRS)
}

// MapCreateWithCommon creates a map with common syscall attributes.
func MapCreateWithCommon(attr *MapCreateAttr, common *CommonAttr) (*FD, error) {
	fd, err := BPFWithCommonAttrs(BPF_MAP_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr), common)
	if err != nil {
		return nil, err
	}
	return NewFD(int(fd))
}
