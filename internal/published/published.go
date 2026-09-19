// Package published writes a finished session in the account contract
// (contract/account): the contract account projected from the operational
// account the session sealed.
//
// It is written at seal, not derived later, so it travels with the run and
// does not depend on a spool that may have been rotated or left behind. It
// carries totals and identities, never payload, headers or bodies.
//
// Reconstruction runs when a capture is read back, so the sealed account's
// reconstruction is not_carried (not supplied by this producer) - not
// unavailable, and holding no totals.
//
// Records is the read side: a session's spool in the record contracts, with
// its reconstruction. It is never written at seal, since that would be a
// second, unbounded copy of the plaintext. Whoever takes a session away
// assembles a bundle from the sealed account and Records (contract.Bundle).
package published

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"

	observed "github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/connection"
	contract "github.com/evandukss/edge-observer/contract/account"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/reconstruct"
	"github.com/evandukss/edge-observer/spool"
)

// Name is the file a session seals its contract account in, beside the
// operational account and the spool.
const Name = "contract-account.json"

// longestLine is the longest spool line read: a fragment's base64 payload is
// one line.
const longestLine = 16 * 1024 * 1024

// Records is a session's spool in the record contracts: fragments as
// observations, connection records as connections, and their reconstruction.
func Records(session fs.FS) (contract.Records, error) {
	fragments, err := read[fragment.Record](session, spool.Name)
	if err != nil {
		return contract.Records{}, err
	}
	connections, err := read[connection.Record](session, spool.ConnectionsName)
	if err != nil {
		return contract.Records{}, err
	}
	records := contract.Records{
		Observations: make([]record.Observation, 0, len(fragments)),
		Connections:  make([]record.Connection, 0, len(connections)),
	}
	for index, one := range fragments {
		observation, err := record.FromFragment(one)
		if err != nil {
			return contract.Records{}, fmt.Errorf("%s line %d: %w", spool.Name, index+1, err)
		}
		records.Observations = append(records.Observations, observation)
	}
	for index, one := range connections {
		projected, err := record.FromConnection(one)
		if err != nil {
			return contract.Records{}, fmt.Errorf("%s line %d: %w", spool.ConnectionsName, index+1, err)
		}
		records.Connections = append(records.Connections, projected)
	}
	records.Reconstructions, records.Reassembly, err = record.FromReconstruction(
		reconstruct.Run(fragments, reconstruct.DefaultLimits()), fragments)
	if err != nil {
		return contract.Records{}, fmt.Errorf("the reconstruction of %s: %w", spool.Name, err)
	}
	return records, nil
}

// Reconstruct reads a session's fragments back as the exchanges they carried,
// needing neither connection records nor the capturing host. A missing spool
// is an error (fs.ErrNotExist), not a session with no traffic.
func Reconstruct(session fs.FS) (reconstruct.Reconstruction, error) {
	fragments, err := read[fragment.Record](session, spool.Name)
	if err != nil {
		return reconstruct.Reconstruction{}, err
	}
	return reconstruct.Run(fragments, reconstruct.DefaultLimits()), nil
}

// Account is the contract account of a sealed session: everything the
// operational account holds, and reconstruction not carried.
func Account(final observed.Account) (contract.Account, error) {
	return contract.Project(final, contract.NotSupplied())
}

// read is every line of one spool file, decoded. A missing file is an error: a
// sealed session always has both.
func read[T any](session fs.FS, name string) ([]T, error) {
	file, err := session.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = file.Close() }()

	out := []T{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), longestLine)
	for line := 1; scanner.Scan(); line++ {
		var one T
		if err := json.Unmarshal(scanner.Bytes(), &one); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", name, line, err)
		}
		out = append(out, one)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return out, nil
}
