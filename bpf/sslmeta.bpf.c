// SPDX-License-Identifier: GPL-2.0

//go:build ignore

// The metadata-only probe: it reads no process memory. It reports which
// process, which connection, which direction, how many bytes when the count is
// in a register, and when - and nothing a body could be reconstructed from.
// Every build embeds it beside the full program; the observer loads the full
// one.
#define READ_PAYLOAD 0
#include "ssl.bpf.h"
