package config

import "embed"

// Examples is the contract's example documents, the files under examples/, so a
// reader of configurations elsewhere in this module is held to them without
// naming a path into this package.
//
//go:embed examples
var Examples embed.FS
