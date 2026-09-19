// SPDX-License-Identifier: MPL-2.0 OR GPL-2.0-only

//go:build ignore

// The full plaintext probe: it reads the caller's buffer and reports the bytes
// that crossed. It is the program the observer loads.
#define READ_PAYLOAD 1
#include "ssl.bpf.h"
