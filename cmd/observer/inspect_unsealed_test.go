package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectRecognizesUnsealedSessionControlState(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, sessionsName, "interrupted-session")
	if err := os.MkdirAll(filepath.Join(directory, controlName), 0700); err != nil {
		t.Fatal(err)
	}
	// Approved output is shared outside the session directory. Inspection must
	// classify the unsealed session without reading that output as an account.
	if err := os.WriteFile(filepath.Join(root, "approved.jsonl"), []byte("not an account\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, text := range []bool{false, true} {
		args := []string{"inspect", directory}
		if text {
			args = append(args, "--text")
		}
		var out bytes.Buffer
		err := run(args, &out)
		if !errors.Is(err, errNeverSealed) || out.Len() != 0 {
			t.Errorf("inspect text=%t: error=%v output=%q; want never sealed and no account", text, err, out.String())
		}
	}
}

func TestInspectRejectsDirectoriesWithoutSessionState(t *testing.T) {
	for _, name := range []string{"empty", "unrelated_directory", "control_is_a_file"} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			switch name {
			case "unrelated_directory":
				if err := os.Mkdir(filepath.Join(directory, "unrelated"), 0700); err != nil {
					t.Fatal(err)
				}
			case "control_is_a_file":
				if err := os.WriteFile(filepath.Join(directory, controlName), []byte("unrelated"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, text := range []bool{false, true} {
				args := []string{"inspect", directory}
				if text {
					args = append(args, "--text")
				}
				var out bytes.Buffer
				err := run(args, &out)
				if !errors.Is(err, errNotASession) || out.Len() != 0 {
					t.Errorf("inspect text=%t: error=%v output=%q; want not a session and no account", text, err, out.String())
				}
			}
		})
	}
}
