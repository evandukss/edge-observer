package main

import (
	"fmt"
	"io"
	"os"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

// loadProcessing is the common command entry point. Manifest discovery belongs
// to the deployment loader; until it is wired, no-pack configurations are the
// supported path and enabled packs are refused by the compiler itself.
func loadProcessing(path string) (policy.Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return policy.Policy{}, fmt.Errorf("read the configuration: %w", err)
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, config.MaxProcessingBytes+1))
	if err != nil {
		return policy.Policy{}, fmt.Errorf("read the configuration: %w", err)
	}
	return policy.CompileProcessing(content, nil)
}
