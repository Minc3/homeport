package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// The database is not readable by anyone but its owner, and neither is its
// journal.
//
// SQLite creates these honouring the umask, which under systemd is 022, so
// they landed at 0644 in a state directory that was itself 0755. What is in
// them is the reason this is a test rather than a preference: portal session
// tokens are stored in the clear beside the password hashes, so any local
// account able to read the file could lift a live thirty-day cookie, and the
// portal behind that cookie serves the shared secret, arms the data plane and
// reverts it. The credential is not the database; it is every credential in
// the system.
//
// The -wal and -shm files matter as much as the database. They carry committed
// pages that have not been checkpointed yet, so a token written in the last
// few seconds may exist only there.
func TestTheDatabaseAndItsJournalAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Chmod there sets a read-only bit rather than a mode, so there is no
		// group or world bit for this to assert about. Development happens on
		// Windows and deployment is Debian; this is a property of the
		// deployment.
		t.Skip("POSIX file modes only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "failover.db")

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// Force a write so the journal exists and holds something worth protecting.
	if err := st.CreateUser("admin", "a-password-long-enough"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.NewSession("admin", 48*time.Hour); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		"failover.db", "failover.db-wal", "failover.db-shm",
		// Present instead of the WAL pair on a filesystem that cannot support
		// WAL, and holding the same pages.
		"failover.db-journal",
	} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			continue // SQLite may have checkpointed it away; the directory covers that
		}
		if mode := fi.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("%s is mode %04o, want no group or world bits: it holds live session tokens", name, mode)
		}
	}
}
