// broken-extension is a deliberately faulty peer for exercising supervision.
// Its wire shapes come from contract/extension/PROTOCOL.md.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const modes = "unchanged, record, loop, cpu, ignore-term, crash, blocked-stdin, oversized, malformed, protocol, unknown-id, read-only, not-given, removed-content, excluded, replacement, derived-flood, stderr-flood, race, descendant, duplicate, late, declined, summary, hold-first"

func main() {
	mode := flag.String("mode", "unchanged", "behaviour: "+modes)
	record := flag.String("record", "", "append received messages and sent results as JSONL to this file")
	count := flag.Int("count", 3, "crash after this many exchanges; flood emits this many records (0 means forever)")
	delay := flag.Duration("delay", 0, "delay before a result (race defaults to start.timeout_ms)")
	first := flag.Bool("first-generation", false, "fault only in generation 1; later generations answer unchanged")
	child := flag.Bool("child", false, "internal descendant holding stdout and ignoring TERM")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Build: go build -o /tmp/broken-extension ./internal/cmd/broken-extension")
		fmt.Fprintln(os.Stderr, "Run as an observer extension. Every mode answers ready before misbehaving.\nFor blocked-stdin, ready is the last input read. record receives everything including lifecycle.\nloop and ignore-term consume exchanges without answering; cpu burns CPU while answering.\nFailures are intentionally unsafe: run only in a disposable test environment.")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 0 || !strings.Contains(", "+modes+",", ", "+*mode+",") || *count < 0 {
		flag.Usage()
		os.Exit(2)
	}
	if *child {
		signal.Ignore(syscall.SIGTERM)
		for {
			time.Sleep(time.Hour)
		}
	}
	var audit *os.File
	if *record != "" {
		var err error
		audit, err = os.OpenFile(*record, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			panic(err)
		}
		defer func() { _ = audit.Close() }()
	}
	var mu sync.Mutex
	log := func(v any) {
		if audit != nil {
			if err := json.NewEncoder(audit).Encode(v); err != nil {
				panic(err)
			}
		}
	}
	log(map[string]any{"process": os.Getpid()})
	send := func(v any) {
		mu.Lock()
		defer mu.Unlock()
		// The audit marks the send before writing: a next exchange arriving
		// before this marker is independently observable as an overlap.
		if m, ok := v.(map[string]any); ok && (m["type"] == "result" || m["type"] == "ready") {
			log(map[string]any{"sent": v})
		}
		if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
			os.Exit(0)
		}
	}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 34<<20)
	n := 0
	var sources []string
	var timeout time.Duration
	term := make(chan os.Signal, 1)
	if *mode == "late" {
		signal.Notify(term, syscall.SIGTERM)
		defer signal.Stop(term)
	}
	for scan.Scan() {
		var msg map[string]any
		if err := json.Unmarshal(scan.Bytes(), &msg); err != nil {
			panic(err)
		}
		mu.Lock()
		log(msg)
		mu.Unlock()
		switch msg["type"] {
		case "start":
			if *first && msg["generation"] != "1" {
				*mode = "unchanged"
			}
			timeout = time.Duration(msg["timeout_ms"].(float64)) * time.Millisecond
			if *mode == "ignore-term" || *mode == "descendant" {
				signal.Ignore(syscall.SIGTERM)
			}
			if *mode == "cpu" {
				go func() {
					var x uint64
					for {
						x = x*1664525 + 1013904223
						if x == 0 {
							fmt.Fprint(os.Stderr, "")
						}
					}
				}()
			}
			if *mode == "descendant" {
				c := exec.Command(os.Args[0], "--child")
				c.Stdout, c.Stderr = os.Stdout, os.Stderr
				if err := c.Start(); err != nil {
					panic(err)
				}
				log(map[string]any{"descendant": c.Process.Pid})
			}
			send(map[string]any{"type": "ready", "protocol": "observer.extension/1"})
			if *mode == "blocked-stdin" {
				for {
					time.Sleep(time.Hour)
				}
			}
		case "exchange":
			n++
			id := msg["id"].(string)
			sources = append(sources, id)
			result := map[string]any{"type": "result", "id": id, "outcome": "unchanged"}
			switch *mode {
			case "late":
				<-term
				send(result)
				for {
					time.Sleep(time.Hour)
				}
			case "loop", "ignore-term":
				continue
			case "hold-first":
				if n == 1 {
					continue
				}
			case "crash":
				if n >= *count {
					os.Exit(23)
				}
				continue
			case "oversized":
				// One unfinished frame exactly at the documented bound. Repeating
				// it would hide a reader that incorrectly allows a larger frame.
				if n == 1 {
					_, _ = fmt.Fprint(os.Stdout, strings.Repeat("x", 4<<20))
				}
				continue
			case "protocol":
				_, _ = fmt.Fprintln(os.Stdout, `{"type":"unrecognised"}`)
				continue
			case "unknown-id":
				result["id"] = "18446744073709551615"
			case "malformed":
				result["outcome"] = ""
			case "declined":
				result["outcome"], result["reason"] = "failed", "reason\x1b\t"+strings.Repeat("x", 500)
			case "read-only":
				result["outcome"], result["changes"] = "changed", map[string]any{"request.line": map[string]any{"method": "PUT", "target": "/changed", "protocol": "HTTP/1.1", "complete": true}}
			case "not-given":
				result["outcome"], result["changes"] = "changed", map[string]any{
					"request.line":  map[string]any{"method": "PUT", "target": "/changed", "protocol": "HTTP/1.1"},
					"response.line": map[string]any{"status": 201, "reason": "Changed", "protocol": "HTTP/1.1"},
				}
			case "removed-content", "replacement":
				result["outcome"], result["changes"] = "changed", map[string]any{"request.body": map[string]any{"kept": base64.StdEncoding.EncodeToString([]byte(`{"items":["remove-this","keep-this"]}`))}}
			case "excluded":
				if msg["output"].(map[string]any)["state"] != "excluded" {
					break
				}
				result["outcome"], result["changes"] = "changed", map[string]any{"request.line": map[string]any{"method": "PUT", "target": "/changed", "protocol": "HTTP/1.1"}}
			case "derived-flood":
				for i := 0; *count == 0 || i < *count; i++ {
					send(map[string]any{"type": "derived", "sources": []string{id}, "basis": "observed", "record": map[string]any{"n": strconv.Itoa(i), "padding": strings.Repeat("d", 8192)}})
				}
			case "stderr-flood":
				floodStderr(os.Stderr, *count)
			}
			d := *delay
			if *mode == "race" && d == 0 {
				d = timeout
			}
			if d > 0 {
				time.Sleep(d)
			}
			send(result)
			if *mode == "duplicate" {
				send(result)
			}
		case "session_ending":
			if *mode == "summary" && len(sources) > 0 {
				send(map[string]any{"type": "derived", "sources": sources, "basis": "inferred", "record": map[string]any{"summary": len(sources)}})
			}
		case "shutdown":
			if *mode == "ignore-term" || *mode == "descendant" {
				for {
					time.Sleep(time.Hour)
				}
			}
			return
		}
	}
}

// floodStderr reuses its line so the traffic generator's allocations do not
// grow with the workload whose receiver is being measured.
func floodStderr(w io.Writer, count int) {
	line := []byte("stderr\x1b\t" + strings.Repeat("s", 4096) + "\n")
	for i := 0; count == 0 || i < count; i++ {
		_, _ = w.Write(line)
	}
}
