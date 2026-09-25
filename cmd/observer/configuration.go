package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

// packsDirectory is where the packs a configuration enables are read from:
// beside the configuration file, one file per pack, packs/<name>.json.
const packsDirectory = "packs"

// packName is the rule an enabled pack's name meets before it becomes a file
// name. It is checked before anything is opened, so a name can never reach
// outside the packs directory.
var packName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Why an enabled pack is refused before it is compiled, as published in
// contract/config/CONFIG.md. A missing pack is config.UnknownPack and a bundle
// over the byte budget is config.ConfigurationTooLarge, the compiler's own
// reasons; a malformed manifest is refused with the structural reader's.
const (
	packNameInvalid  config.Reason = "pack_name_invalid"
	packUnreadable   config.Reason = "pack_unreadable"
	packNotRegular   config.Reason = "pack_not_regular_file"
	packNameMismatch config.Reason = "pack_name_mismatch"
)

// loadProcessing is the common command entry point for everything that
// compiles: start, daemonize, restart, dry-run, preflight and both halves of
// reload. It reads the configuration and every pack it enables, from
// packs/<name>.json in the configuration's directory and in the configuration's
// order, and compiles them together. A pack that cannot be read as the one
// named is refused before capture; it never means continuing without it.
func loadProcessing(path string) (policy.Policy, error) {
	content, err := readConfiguration(path)
	if err != nil {
		return policy.Policy{}, err
	}
	if len(content) > config.MaxProcessingBytes {
		return policy.CompileProcessing(content, nil)
	}
	written, structural := config.ReadConfiguration(content)
	if len(structural) > 0 || len(written.Packs) > config.MaxProcessingPacks {
		// Refused before any pack is opened, in the compiler's words.
		return policy.CompileProcessing(content, nil)
	}
	manifests, findings := loadPacks(filepath.Join(filepath.Dir(path), packsDirectory), written.Packs,
		config.MaxProcessingBytes-len(content))
	if len(findings) > 0 {
		return policy.Policy{}, &policy.Refused{Outcome: policy.ProcessingRefused, Findings: findings}
	}
	return policy.CompileProcessing(content, manifests)
}

// sessionDirectory is where a configuration's sessions are held, read
// structurally and nothing more. Stop and a running session's inspect act on
// a session that already exists, so a pack or a processing change that would
// refuse a new session never prevents stopping or inspecting it.
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
	written, structural := config.ReadConfiguration(content)
	if len(structural) > 0 {
		return "", &policy.Refused{Outcome: config.StructurallyRefused, Findings: structural}
	}
	return written.Observer.Directory, nil
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

// loadPacks reads each named pack from directory, within budget bytes in all.
// Every name is checked before anything is opened; each file is opened without
// blocking and checked to be a regular file before a byte is read, so a FIFO
// cannot hold the command; and no more than one byte past the budget is ever
// read, so an oversized bundle is refused before its excess is.
func loadPacks(directory string, names []string, budget int) ([]config.Supplied, []config.Finding) {
	var findings []config.Finding
	refuse := func(document, name string, reason config.Reason, detail string, arguments ...any) {
		findings = append(findings, config.Finding{Document: document, Subject: "pack:" + name, Reason: reason,
			Detail: fmt.Sprintf(detail, arguments...)})
	}
	for _, name := range names {
		if !packName.MatchString(name) {
			refuse("configuration", name, packNameInvalid, "%q does not match %s, so no file is looked for",
				name, packName.String())
		}
	}
	if len(findings) > 0 {
		return nil, findings
	}

	var supplied []config.Supplied
	for _, name := range names {
		at := filepath.Join(directory, name+".json")
		content, reason, detail := readPack(at, budget)
		if reason != "" {
			refuse("configuration", name, reason, "%s: %s", at, detail)
			if reason == config.ConfigurationTooLarge {
				// The budget is spent: nothing after this pack can be read within it.
				break
			}
			continue
		}
		budget -= len(content)
		manifest, structural := config.ReadManifest(config.Supplied{Name: name, Content: content})
		if len(structural) > 0 {
			for _, finding := range structural {
				finding.Detail = at + ": " + finding.Detail
				findings = append(findings, finding)
			}
			continue
		}
		if manifest.Name != name {
			refuse("manifest:"+name, name, packNameMismatch, "%s declares the pack %q, and the configuration enables %q "+
				"from that file", at, manifest.Name, name)
			continue
		}
		supplied = append(supplied, config.Supplied{Name: name, Content: content})
	}
	return supplied, findings
}

// readPack reads one pack file, or says why it cannot be the pack.
func readPack(at string, budget int) ([]byte, config.Reason, string) {
	file, err := os.OpenFile(at, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, config.UnknownPack, "no such file; a pack is installed by placing its manifest there"
	case err != nil:
		return nil, packUnreadable, err.Error()
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, packUnreadable, err.Error()
	}
	if !info.Mode().IsRegular() {
		return nil, packNotRegular, fmt.Sprintf("it is %s, and a pack is a regular file", describeMode(info.Mode()))
	}
	tooLarge := fmt.Sprintf("the configuration and the enabled packs exceed %d encoded bytes", config.MaxProcessingBytes)
	if info.Size() > int64(budget) {
		return nil, config.ConfigurationTooLarge, tooLarge
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(budget)+1))
	if err != nil {
		return nil, packUnreadable, err.Error()
	}
	if len(content) > budget {
		// It grew after it was measured.
		return nil, config.ConfigurationTooLarge, tooLarge
	}
	return content, "", ""
}

func describeMode(mode fs.FileMode) string {
	switch {
	case mode.IsDir():
		return "a directory"
	case mode&fs.ModeNamedPipe != 0:
		return "a named pipe"
	case mode&fs.ModeSocket != 0:
		return "a socket"
	case mode&fs.ModeDevice != 0:
		return "a device"
	default:
		return "not a regular file (" + mode.Type().String() + ")"
	}
}
