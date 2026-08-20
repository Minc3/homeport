package store_test

import (
	"path/filepath"
	"testing"

	"github.com/quinlan102/homeport/internal/store"
)

// HasConfig is what tells a first-ever start from every later one, and it has to
// answer before LoadConfig seeds the defaults. The frontend uses it to decide
// whether the bootstrap file's public interface may be planted in the config:
// once on a fresh database, never afterwards, so the portal stays authoritative.
func TestHasConfigIsFalseOnlyUntilTheDefaultsAreSeeded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failover.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	has, err := st.HasConfig()
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("a fresh database must report no configuration, or the seed never happens")
	}

	if _, err := st.LoadConfig(); err != nil {
		t.Fatal(err)
	}

	has, err = st.HasConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("after LoadConfig has seeded the defaults this must report configured, or the seed repeats on every start and overwrites the operator's choice")
	}
}
