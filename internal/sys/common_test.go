package sys

import (
	"errors"
	"fmt"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
	"github.com/go-quicktest/qt"
)

func TestCommonAttrLayout(t *testing.T) {
	var attr CommonAttr
	qt.Assert(t, qt.Equals(unsafe.Sizeof(attr), uintptr(24)))
	qt.Assert(t, qt.Equals(unsafe.Offsetof(attr.LogSize), uintptr(8)))
	qt.Assert(t, qt.Equals(unsafe.Offsetof(attr.LogLevel), uintptr(12)))
	qt.Assert(t, qt.Equals(unsafe.Offsetof(attr.LogTrueSize), uintptr(16)))
}

func TestMapCreateWithCommon(t *testing.T) {
	if err := HaveCommonAttrs(); errors.Is(err, internal.ErrNotSupported) {
		t.Skip(err)
	} else {
		qt.Assert(t, qt.IsNil(err))
	}

	t.Run("success", func(t *testing.T) {
		fd, err := MapCreateWithCommon(&MapCreateAttr{
			MapType: BPF_MAP_TYPE_ARRAY, KeySize: 4, ValueSize: 4, MaxEntries: 1,
		}, &CommonAttr{})
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsNil(fd.Close()))
	})

	for _, size := range []int{1, 4096} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			buf := make([]byte, size)
			common := CommonAttr{LogBuf: UnsafeSlicePointer(buf), LogSize: uint32(size), LogLevel: 1}
			fd, err := MapCreateWithCommon(&MapCreateAttr{
				MapType: BPF_MAP_TYPE_ARRAY, KeySize: 4, ValueSize: 4, MaxEntries: 1,
				MapExtra: 1,
			}, &common)
			if fd != nil {
				fd.Close()
				t.Fatal("invalid map was created")
			}
			if size == 1 {
				qt.Assert(t, qt.ErrorIs(err, unix.ENOSPC))
				qt.Assert(t, qt.IsTrue(common.LogTrueSize > uint32(size)))
			} else {
				qt.Assert(t, qt.ErrorIs(err, unix.EINVAL))
				qt.Assert(t, qt.StringContains(unix.ByteSliceToString(buf), "map_extra"))
			}
		})
	}
}
