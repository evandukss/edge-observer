package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

// loadProcessing is the common command entry point for everything that
// compiles: start, daemonize, restart, dry-run, preflight and both halves of
// reload. It reads the configuration and compiles it, resolving each
// extension's command against the configuration's directory; a command that
// is not an executable regular file is refused here, before capture, naming
// the entry.
func loadProcessing(path string) (policy.Policy, error) {
	content, err := readConfiguration(path)
	if err != nil {
		return policy.Policy{}, err
	}
	return policy.CompileProcessing(content, filepath.Dir(path))
}

// sessionDirectory is where a configuration's sessions are held, read
// structurally and nothing more. Stop and a running session's inspect act on
// a session that already exists, so a missing extension command or a
// processing change that would refuse a new session never prevents stopping or
// inspecting it.
func sessionDirectory(path string) (string, error) {
	content, err := readConfiguration(path)
	if err != nil {
		return "", err
	}
	if len(content) > config.MaxProcessingBytes {
		return "", &policy.Refused{Outcome: config.StructurallyRefused, Findings: []config.Finding{{
			Document: "configuration", Reason: config.ConfigurationTooLarge,
			Detail: fmt.Sprintf("configuration exceeds %d encoded bytes", config.MaxProcessingBytes)}}}
	}
	file, findings := config.ReadFile(content)
	if len(findings) > 0 {
		return "", &policy.Refused{Outcome: config.StructurallyRefused, Findings: findings}
	}
	return file.Output, nil
}

// readConfiguration reads at most one byte past the budget, so an oversized
// configuration is refused without being read whole.
func readConfiguration(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read the configuration: %w", err)
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, config.MaxProcessingBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read the configuration: %w", err)
	}
	return content, nil
}
