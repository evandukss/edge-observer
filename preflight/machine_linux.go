package preflight

import "syscall"

func machine() (string, error) {
	var name syscall.Utsname
	if err := syscall.Uname(&name); err != nil {
		return "", err
	}
	// The element type is int8 on some architectures and uint8 on others.
	var machine []byte
	for _, c := range name.Machine {
		if c == 0 {
			break
		}
		machine = append(machine, byte(c))
	}
	return string(machine), nil
}
