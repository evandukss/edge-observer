// Package mapslots reads how many slots a map's tables hold, from the
// runtime's own layout, for tests that measure what a map allocates rather
// than what it holds. It knows one layout, Go 1.27's (internal/runtime/maps),
// checks every reading against what the map itself reports, and refuses any
// other runtime or any inconsistent reading rather than guess.
package mapslots

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"unsafe"
)

// header is the leading fields of internal/runtime/maps.Map.
type header struct {
	used      uint64
	seed      uintptr
	directory unsafe.Pointer
	length    int
}

// table is the leading fields of internal/runtime/maps.table.
type table struct {
	used     uint16
	capacity uint16
}

// smallGroup is the slots of a map small enough to hold one group and no
// table: its directory pointer is the group itself.
const smallGroup = 8

// Slots is how many slots the tables of m, a map, hold.
func Slots(m any) (int, error) {
	if !strings.HasPrefix(runtime.Version(), "go1.27") || unsafe.Sizeof(uintptr(0)) != 8 {
		return 0, fmt.Errorf("the map layout is known for 64-bit go1.27, not %s on %s", runtime.Version(), runtime.GOARCH)
	}
	v := reflect.ValueOf(m)
	if v.Kind() != reflect.Map {
		return 0, fmt.Errorf("%T is not a map", m)
	}
	if v.IsNil() {
		return 0, nil
	}
	h := (*header)(v.UnsafePointer())
	if int(h.used) != v.Len() {
		return 0, fmt.Errorf("the header counts %d entries and the map holds %d", h.used, v.Len())
	}
	if h.length == 0 {
		if h.directory == nil {
			return 0, nil
		}
		return smallGroup, nil
	}
	seen := make(map[*table]bool, h.length)
	slots, used := 0, 0
	for _, t := range unsafe.Slice((**table)(h.directory), h.length) {
		if seen[t] {
			continue
		}
		seen[t] = true
		if t.capacity < smallGroup || t.capacity&(t.capacity-1) != 0 || t.used > t.capacity {
			return 0, fmt.Errorf("a table reads capacity %d holding %d", t.capacity, t.used)
		}
		slots += int(t.capacity)
		used += int(t.used)
	}
	if used != v.Len() {
		return 0, fmt.Errorf("the tables hold %d entries and the map holds %d", used, v.Len())
	}
	runtime.KeepAlive(m)
	return slots, nil
}
