package main

import (
	"crypto/sha256"
	"fmt"
	"os"
)

// The attach tests build this package as a test executable. The driver runs
// the real command, including its detached child, but changes the file exactly
// after checkDetached returns. It does not replace holder, stop or launch.
func init() {
	if os.Getenv("OBSERVER_RESTART_TEST_DRIVER") != "1" {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "restart" {
		check := restarting.check
		restarting.check = func(path string) (checked, error) {
			c, err := check(path)
			if err != nil {
				return c, err
			}
			replacement, err := os.ReadFile(os.Getenv("OBSERVER_RESTART_TEST_REPLACEMENT"))
			if err != nil {
				return c, err
			}
			if err := os.WriteFile(path, replacement, 0o600); err != nil {
				return c, err
			}
			receipt := fmt.Sprintf("%x\n%x\n", sha256.Sum256(c.content), sha256.Sum256(replacement))
			if err := os.WriteFile(os.Getenv("OBSERVER_RESTART_TEST_RECEIPT"), []byte(receipt), 0o600); err != nil {
				return c, err
			}
			return c, nil
		}
	}
	main()
	os.Exit(0)
}
