// Package privhome points yaklang's working directory at a private folder.
//
// Some yaklang packages create directories under YAKIT_HOME (default
// ~/yakit-projects) while they initialise. This package has no yaklang imports
// and its import path sorts before common/..., so Go initialises it first and
// the env var is set before those packages run.
package privhome

import (
	"os"
	"path/filepath"
)

func init() {
	if os.Getenv("YAKIT_HOME") != "" {
		return
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		base = filepath.Join(home, ".local", "state")
	}
	dir := filepath.Join(base, "yaklite", "engine")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	_ = os.Chmod(filepath.Join(base, "yaklite"), 0o700)
	os.Setenv("YAKIT_HOME", dir)
}
