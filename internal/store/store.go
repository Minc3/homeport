// Package store is the frontend's durable state: configuration, the LTE usage
// ledger, path history for the portal's graphs, and the event log.
//
// SQLite is used through a pure-Go driver so the binaries stay statically
// linked with CGO disabled.
package store

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"github.com/quinlan102/homeport/internal/model"
)

// ErrNotFound is returned when a lookup misses.
var ErrNotFound = errors.New("store: not found")

// MaxLedgerValue is the ceiling on one accumulated ledger figure.
//
// 2^60 is an exbibyte, so no real deployment approaches it and the cap never
// bites anything honest. It is low enough that adding one more bounded delta to
// a column already at the cap cannot overflow an int64, which is the property
// that matters: see the note in AddUsageBatch on what SQLite does with an
// overflow.
const MaxLedgerValue = 1 << 60

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB

	// permIssues records what restrict could not do at open, for the caller to
	// report. See PermissionWarnings.
	permIssues []error
}

const schema = `
CREATE TABLE IF NOT EXISTS config (
	id      INTEGER PRIMARY KEY CHECK (id = 1),
	json    TEXT NOT NULL,
	updated INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
	username  TEXT PRIMARY KEY,
	salt      TEXT NOT NULL,
	hash      TEXT NOT NULL,
	created   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	token    TEXT PRIMARY KEY,
	username TEXT NOT NULL,
	expires  INTEGER NOT NULL
);

-- Accumulated metered usage for one path in one billing period. This is the
-- authoritative number quotas are enforced against, and it survives restarts
-- and interface counter resets.
CREATE TABLE IF NOT EXISTS ledger (
	path_id      INTEGER NOT NULL,
	period_start INTEGER NOT NULL,
	bytes        INTEGER NOT NULL DEFAULT 0,
	packets      INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (path_id, period_start)
);

-- Per-sample usage, kept for the portal's usage graphs.
CREATE TABLE IF NOT EXISTS usage_samples (
	ts      INTEGER NOT NULL,
	path_id INTEGER NOT NULL,
	bytes   INTEGER NOT NULL,
	packets INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage_samples (ts);

-- Per-sample path quality, kept for the portal's health graphs.
CREATE TABLE IF NOT EXISTS path_samples (
	ts      INTEGER NOT NULL,
	path_id INTEGER NOT NULL,
	rtt_ms  REAL NOT NULL,
	loss    REAL NOT NULL,
	jitter  REAL NOT NULL,
	health  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_path_ts ON path_samples (ts);

-- Switches, path failures, quota events, approvals.
CREATE TABLE IF NOT EXISTS events (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	ts      INTEGER NOT NULL,
	kind    TEXT NOT NULL,
	path_id INTEGER,
	message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts DESC);

-- Time-boxed permission to use a path that is over its quota. Deliberately
-- expiring: one 2am approval must not silently disable quota enforcement for
-- the rest of the month.
CREATE TABLE IF NOT EXISTS grants (
	path_id     INTEGER PRIMARY KEY,
	until       INTEGER NOT NULL,
	extra_bytes INTEGER NOT NULL DEFAULT 0,
	start_bytes INTEGER NOT NULL DEFAULT 0,
	created     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

// Open opens or creates the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite writers serialise anyway; avoids lock churn
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db, permIssues: restrict(path)}, nil
}

// PermissionWarnings reports files whose mode could not be tightened, so the
// caller can say so.
//
// Returning them rather than swallowing them is the point. restrict is a
// security property, not a tidy-up: a chmod that silently did nothing leaves
// live thirty-day session tokens world-readable beside the password hashes,
// and the journal says the frontend started normally. That is reachable
// without anything exotic - a filesystem that ignores chmod, or an export
// where this process is not the file's owner - and the test beside this runs
// on tmpfs, where it can never happen. A hardening step that can fail in
// silence is a hardening step nobody knows they have lost.
func (s *Store) PermissionWarnings() []error { return s.permIssues }

// restrict takes the group and world bits off the database and its journal.
//
// SQLite creates these honouring the umask, which under systemd is 022 - so
// they land at 0644 in a state directory that is itself 0755, and this file
// holds portal session tokens in the clear alongside the password hashes.
// Anything able to read it can lift a live thirty-day cookie, and the portal
// behind that cookie will hand over the shared secret, arm the data plane or
// revert it. The credential is not the database, it is every credential in the
// system.
//
// Belt and braces with the state directory's own mode, which is set in three
// places because each covers a moment the others miss: install-frontend.sh
// creates it 0700 and corrects an existing one, StateDirectoryMode covers a
// directory systemd creates itself, and the agent chmods it on every start for
// the deployments that predate both. The directory is what covers the -wal and
// -shm files whenever SQLite recreates them after a checkpoint; this covers a
// db_path pointed somewhere else entirely.
//
// Failures are returned for the caller to report rather than being fatal. A
// database that opened is a database the frontend can run on, and refusing to
// start over a mode bit would trade a hardening step for the outage it exists
// to prevent - but they are returned rather than dropped, because a mode this
// file's contents depend on must not be able to fail without saying so. See
// Store.PermissionWarnings.
func restrict(path string) []error {
	var issues []error
	// The rollback journal is on the list beside the WAL pair because WAL is
	// requested rather than guaranteed: a filesystem that cannot support it
	// leaves SQLite in journal mode, and that file holds the same pages.
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if _, err := os.Stat(p); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				// Not created yet is the ordinary case and says nothing; being
				// unable to tell is not the same answer and must not read as
				// one, because the file may well be there at 0644.
				issues = append(issues, fmt.Errorf("cannot inspect %s: %w", p, err))
			}
			continue
		}
		if err := os.Chmod(p, 0o600); err != nil {
			issues = append(issues, fmt.Errorf("cannot restrict %s to 0600: %w", p, err))
		}
	}
	return issues
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// HasConfig reports whether a configuration has ever been stored.
//
// It exists so a caller can tell a first-ever start from every later one
// *before* LoadConfig seeds the defaults, which is the only moment a bootstrap
// value may be planted in the config without overriding an operator's choice.
func (s *Store) HasConfig() (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM config WHERE id = 1`).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check config: %w", err)
	}
	return true, nil
}

// LoadConfig returns the stored configuration, seeding defaults on first run.
func (s *Store) LoadConfig() (model.Config, error) {
	var raw string
	err := s.db.QueryRow(`SELECT json FROM config WHERE id = 1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		cfg := model.Defaults()
		if err := s.SaveConfig(cfg); err != nil {
			return cfg, err
		}
		return cfg, nil
	}
	if err != nil {
		return model.Config{}, fmt.Errorf("load config: %w", err)
	}
	var cfg model.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return model.Config{}, fmt.Errorf("decode config: %w", err)
	}
	// A config stored by an older build has no value at all for anything added
	// since, and unmarshalling leaves those fields zero. Without this every
	// existing deployment inherits a zero for each new setting while a fresh
	// install gets the shipped default.
	model.Normalise(&cfg)
	return cfg, nil
}

// SaveConfig replaces the stored configuration.
func (s *Store) SaveConfig(cfg model.Config) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO config (id, json, updated) VALUES (1, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET json = excluded.json, updated = excluded.updated`,
		string(raw), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Usage ledger
// ---------------------------------------------------------------------------

// AddUsage accumulates a metered delta against a path's current period and
// records the sample for graphing.
//
// A non-empty metaKey is written in the same transaction. The caller's key is
// the per-path ack watermark, and it must not be able to drift from the ledger
// across a crash in either direction: written first, a crash loses the bytes
// for good (the ack tells the backend to drop its copy); written second, a
// crash has the backend resend a delta the watermark no longer filters, and
// the same LTE bytes are billed twice.
//
// A batch of one, and that is not tidiness. When this held its own copy of the
// SQL, it was the method every test in this package drove and the method
// nothing in production called, so the bounds the batch path actually uses -
// the saturating ledger upsert, the floor under it, the usage_samples insert
// the portal's graph reads back - were pinned only on the dead copy. Dropping
// the floor from the live one left the suite green.
func (s *Store) AddUsage(pathID int, periodStart time.Time, bytes, packets int64, at time.Time, metaKey, metaValue string) error {
	return s.AddUsageBatch(pathID, []UsageEntry{{
		PeriodStart: periodStart, At: at, Bytes: bytes, Packets: packets,
	}}, metaKey, metaValue)
}

// UsageEntry is one metered delta as the ledger takes it: already converted,
// already clamped, already assigned to a billing period.
type UsageEntry struct {
	PeriodStart time.Time
	At          time.Time
	Bytes       int64
	Packets     int64
}

// AddUsageBatch folds a whole batch for one path into the ledger in a single
// transaction, and advances that path's watermark inside it.
//
// One transaction rather than one per delta, and the cost of the old shape was
// not theoretical. SQLite defaults to synchronous=FULL, so every commit fsyncs
// the WAL, and Open holds MaxOpenConns at 1 - so a five hundred delta backlog
// was five hundred fsyncs with every other reader in the process queued behind
// them: the portal's own API calls, the quota refresh, the path sample writer.
// A backlog is drained exactly when a failover has just reconnected the control
// channel, which is when an operator is most likely to be looking at the
// portal.
//
// All or nothing per path, which is what the caller's stall behaviour wants
// anyway. If the transaction does not commit, the watermark does not move, the
// caller acks nothing new, and the backend resends the lot. There is no state
// in which the ledger holds part of a batch while the watermark says all of it
// was applied - the failure the metaKey argument exists to prevent, now for a
// batch rather than a delta.
func (s *Store) AddUsageBatch(pathID int, entries []UsageEntry, metaKey, metaValue string) error {
	if len(entries) == 0 {
		if metaKey == "" {
			return nil
		}
		return s.SetMeta(metaKey, metaValue)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Saturating in SQL, in both directions, and not merely bounded per delta
	// by the caller.
	//
	// SQLite does not error on integer overflow: `bytes + excluded.bytes`
	// silently becomes a REAL, and from then on every Scan into an int64
	// returns "converting driver.Value type float64 to a int64". That is
	// permanent, because the column now holds a float, and Engine.refreshQuota
	// carries the previous verdict forward on a read error, so the path's quota
	// freezes at whatever it last was and only editing the database clears it.
	//
	// A per-delta bound cannot prevent it, which is the trap: the callers bound
	// one delta and this column accumulates them, so thirteen clamped deltas
	// reach the overflow inside a single frame. The cap has to be on the sum,
	// which is what MIN does here.
	//
	// MAX(..., 0) is the floor, and it matters more than the ceiling. This
	// column accumulates, so a negative figure does not record a wrong number
	// for one sample, it erases usage already billed - the silent direction, and
	// the one the carrier's invoice is the first news of. Do not simplify either
	// of these to a bare `+`.
	ledger, err := tx.Prepare(
		`INSERT INTO ledger (path_id, period_start, bytes, packets) VALUES (?, ?, ?, ?)
		 ON CONFLICT(path_id, period_start) DO UPDATE SET
		     bytes = MAX(MIN(bytes + excluded.bytes, ?), 0), packets = MAX(MIN(packets + excluded.packets, ?), 0)`)
	if err != nil {
		return fmt.Errorf("ledger update: %w", err)
	}
	defer ledger.Close()
	// The same values, so the same bounds. These rows looked like the harmless
	// half of the pair and are not: the cap above bounds an accumulating
	// column, and these accumulate inside a query instead. See UsageHistory.
	sample, err := tx.Prepare(
		`INSERT INTO usage_samples (ts, path_id, bytes, packets) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("usage sample: %w", err)
	}
	defer sample.Close()

	for _, e := range entries {
		// The same bounds one delta gets, because the batch entry point must
		// not be the way round them. See AddUsage.
		b, pk := clampLedger(e.Bytes), clampLedger(e.Packets)
		if _, err := ledger.Exec(pathID, e.PeriodStart.Unix(), b, pk,
			int64(MaxLedgerValue), int64(MaxLedgerValue)); err != nil {
			return fmt.Errorf("ledger update: %w", err)
		}
		if _, err := sample.Exec(e.At.Unix(), pathID, b, pk); err != nil {
			return fmt.Errorf("usage sample: %w", err)
		}
	}
	if metaKey != "" {
		if _, err := tx.Exec(
			`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			metaKey, metaValue); err != nil {
			return fmt.Errorf("usage watermark: %w", err)
		}
	}
	return tx.Commit()
}

// Usage returns accumulated bytes for a path in a period.
func (s *Store) Usage(pathID int, periodStart time.Time) (int64, error) {
	var b int64
	err := s.db.QueryRow(
		`SELECT bytes FROM ledger WHERE path_id = ? AND period_start = ?`,
		pathID, periodStart.Unix()).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read usage: %w", err)
	}
	return b, nil
}

// UsagePackets returns the accumulated packet count for a path in a period.
//
// It exists because the ledger's two columns are written together and only one
// of them could be read back. The packets column is not decoration: it is what
// quota.Metered multiplies by the per-packet overhead, so a wrong figure there
// under-bills every metered byte exactly as a wrong byte count does, and until
// this there was no way for a test to say so.
func (s *Store) UsagePackets(pathID int, periodStart time.Time) (int64, error) {
	var p int64
	err := s.db.QueryRow(
		`SELECT packets FROM ledger WHERE path_id = ? AND period_start = ?`,
		pathID, periodStart.Unix()).Scan(&p)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read usage packets: %w", err)
	}
	return p, nil
}

// clampLedger brings one figure inside the bounds a ledger column may hold.
func clampLedger(v int64) int64 {
	if v < 0 {
		return 0
	}
	if v > MaxLedgerValue {
		return MaxLedgerValue
	}
	return v
}

// UsagePoint is one bucket of the usage history.
type UsagePoint struct {
	TS    int64 `json:"ts"`
	Bytes int64 `json:"bytes"`
}

// UsageHistory returns bucketed usage for a path over a window.
func (s *Store) UsageHistory(pathID int, since time.Time, bucketSec int) ([]UsagePoint, error) {
	// SUM over REAL rather than over INTEGER, and scanned as a float.
	//
	// SQLite does not promote an overflowing SUM the way it promotes a bare
	// `+`: it fails the whole statement with "integer overflow", so one bucket
	// holding more than an int64 can carry takes the portal's usage graph off
	// the air for that path until the rows age out, which is thirteen months.
	// A per-row ceiling cannot prevent it, because the rows accumulate inside
	// the query - the same trap as the ledger column, reached through a read
	// instead of a write.
	//
	// A float is the right answer here and would not be in the ledger: this
	// feeds a graph, not an enforcement decision, and float64 is exact to about
	// 9e15, which is four orders of magnitude above any bucket a real
	// deployment produces.
	rows, err := s.db.Query(
		`SELECT (ts / ?) * ?, SUM(CAST(bytes AS REAL)) FROM usage_samples
		 WHERE path_id = ? AND ts >= ? GROUP BY 1 ORDER BY 1`,
		bucketSec, bucketSec, pathID, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("usage history: %w", err)
	}
	defer rows.Close()
	var out []UsagePoint
	for rows.Next() {
		var p UsagePoint
		var sum float64
		if err := rows.Scan(&p.TS, &sum); err != nil {
			return nil, err
		}
		switch {
		case sum >= MaxLedgerValue:
			p.Bytes = MaxLedgerValue
		case sum <= 0:
			p.Bytes = 0
		default:
			p.Bytes = int64(sum)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Path history
// ---------------------------------------------------------------------------

// AddPathSample records one quality measurement.
func (s *Store) AddPathSample(pathID int, at time.Time, rtt, loss, jitter float64, health model.Health) error {
	_, err := s.db.Exec(
		`INSERT INTO path_samples (ts, path_id, rtt_ms, loss, jitter, health) VALUES (?, ?, ?, ?, ?, ?)`,
		at.Unix(), pathID, rtt, loss, jitter, string(health))
	return err
}

// PathPoint is one bucket of path history.
type PathPoint struct {
	TS     int64   `json:"ts"`
	RTT    float64 `json:"rtt_ms"`
	Loss   float64 `json:"loss_pct"`
	Jitter float64 `json:"jitter_ms"`
}

// PathHistory returns bucketed quality history for a path.
func (s *Store) PathHistory(pathID int, since time.Time, bucketSec int) ([]PathPoint, error) {
	rows, err := s.db.Query(
		`SELECT (ts / ?) * ?, AVG(rtt_ms), AVG(loss), AVG(jitter) FROM path_samples
		 WHERE path_id = ? AND ts >= ? GROUP BY 1 ORDER BY 1`,
		bucketSec, bucketSec, pathID, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("path history: %w", err)
	}
	defer rows.Close()
	var out []PathPoint
	for rows.Next() {
		var p PathPoint
		if err := rows.Scan(&p.TS, &p.RTT, &p.Loss, &p.Jitter); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

// Event is one entry in the activity log.
type Event struct {
	ID      int64  `json:"id"`
	TS      int64  `json:"ts"`
	Kind    string `json:"kind"`
	PathID  int    `json:"path_id"`
	Message string `json:"message"`
}

// Event kinds.
const (
	EventSwitch     = "switch"
	EventPathDown   = "path_down"
	EventPathUp     = "path_up"
	EventQuota      = "quota"
	EventGrant      = "grant"
	EventHeld       = "held"
	EventQuarantine = "quarantine"
	EventConfig     = "config"
	EventSystem     = "system"
)

// AddEvent appends to the activity log.
func (s *Store) AddEvent(kind string, pathID int, format string, args ...any) error {
	_, err := s.db.Exec(
		`INSERT INTO events (ts, kind, path_id, message) VALUES (?, ?, ?, ?)`,
		time.Now().Unix(), kind, pathID, fmt.Sprintf(format, args...))
	return err
}

// Events returns the most recent log entries.
func (s *Store) Events(limit int) ([]Event, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, kind, COALESCE(path_id, 0), message FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("events: %w", err)
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.Kind, &e.PathID, &e.Message); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Overage grants
// ---------------------------------------------------------------------------

// Grant is a time-boxed permission to use an over-quota path.
type Grant struct {
	PathID     int   `json:"path_id"`
	Until      int64 `json:"until"`
	ExtraBytes int64 `json:"extra_bytes"`
	StartBytes int64 `json:"start_bytes"`
}

// SetGrant records an approval to use a path past its quota.
func (s *Store) SetGrant(g Grant) error {
	_, err := s.db.Exec(
		`INSERT INTO grants (path_id, until, extra_bytes, start_bytes, created) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(path_id) DO UPDATE SET
		     until = excluded.until, extra_bytes = excluded.extra_bytes,
		     start_bytes = excluded.start_bytes, created = excluded.created`,
		g.PathID, g.Until, g.ExtraBytes, g.StartBytes, time.Now().Unix())
	return err
}

// ClearGrant revokes an approval.
func (s *Store) ClearGrant(pathID int) error {
	_, err := s.db.Exec(`DELETE FROM grants WHERE path_id = ?`, pathID)
	return err
}

// Grants returns all live approvals keyed by path id.
func (s *Store) Grants() (map[int]Grant, error) {
	rows, err := s.db.Query(`SELECT path_id, until, extra_bytes, start_bytes FROM grants`)
	if err != nil {
		return nil, fmt.Errorf("grants: %w", err)
	}
	defer rows.Close()
	out := map[int]Grant{}
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.PathID, &g.Until, &g.ExtraBytes, &g.StartBytes); err != nil {
			return nil, err
		}
		out[g.PathID] = g
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Users and sessions
// ---------------------------------------------------------------------------

const pbkdf2Iterations = 600_000

// CreateUser stores a user with a PBKDF2-SHA256 password hash.
func (s *Store) CreateUser(username, password string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	sum, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO users (username, salt, hash, created) VALUES (?, ?, ?, ?)
		 ON CONFLICT(username) DO UPDATE SET salt = excluded.salt, hash = excluded.hash`,
		username, hex.EncodeToString(salt), hex.EncodeToString(sum), time.Now().Unix())
	return err
}

// HasUsers reports whether any account exists, used to decide first-run setup.
func (s *Store) HasUsers() (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// CheckPassword verifies credentials in constant time.
func (s *Store) CheckPassword(username, password string) bool {
	var saltHex, hashHex string
	err := s.db.QueryRow(`SELECT salt, hash FROM users WHERE username = ?`, username).Scan(&saltHex, &hashHex)
	if err != nil {
		return false
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(hashHex)
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewSession issues a session token.
func (s *Store) NewSession(username string, ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	_, err := s.db.Exec(`INSERT INTO sessions (token, username, expires) VALUES (?, ?, ?)`,
		token, username, time.Now().Add(ttl).Unix())
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	return token, nil
}

// Session resolves a token to a username, or ErrNotFound.
func (s *Store) Session(token string) (string, error) {
	var username string
	var expires int64
	err := s.db.QueryRow(`SELECT username, expires FROM sessions WHERE token = ?`, token).Scan(&username, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if time.Now().Unix() > expires {
		_ = s.DeleteSession(token)
		return "", ErrNotFound
	}
	return username, nil
}

// DeleteSession logs a session out.
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// DeleteSessionsFor logs out every session belonging to one account.
//
// Called when a password changes, which is the point of changing it: the reason
// to rotate is usually that somebody else may have the old one, and a thirty-day
// session cookie would let them keep using it regardless.
func (s *Store) DeleteSessionsFor(username string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE username = ?`, username)
	return err
}

// ---------------------------------------------------------------------------
// Meta and retention
// ---------------------------------------------------------------------------

// SetMeta stores a small key/value pair.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	return err
}

// Meta reads a key, returning "" when absent.
func (s *Store) Meta(key string) string {
	var v string
	if err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v); err != nil {
		return ""
	}
	return v
}

// Prune drops history past its retention window and expired sessions. Usage
// samples are kept far longer than quality samples because they back the
// monthly billing view.
func (s *Store) Prune() error {
	now := time.Now()
	if _, err := s.db.Exec(`DELETE FROM path_samples WHERE ts < ?`, now.AddDate(0, 0, -30).Unix()); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM usage_samples WHERE ts < ?`, now.AddDate(0, -13, 0).Unix()); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM events WHERE ts < ?`, now.AddDate(0, 0, -90).Unix()); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE expires < ?`, now.Unix()); err != nil {
		return err
	}
	return nil
}
