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
	"time"

	_ "modernc.org/sqlite"

	"github.com/quinlan102/homeport/internal/model"
)

// ErrNotFound is returned when a lookup misses.
var ErrNotFound = errors.New("store: not found")

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
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
	return &Store{db: db}, nil
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
func (s *Store) AddUsage(pathID int, periodStart time.Time, bytes, packets int64, at time.Time, metaKey, metaValue string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(
		`INSERT INTO ledger (path_id, period_start, bytes, packets) VALUES (?, ?, ?, ?)
		 ON CONFLICT(path_id, period_start) DO UPDATE SET
		     bytes = bytes + excluded.bytes, packets = packets + excluded.packets`,
		pathID, periodStart.Unix(), bytes, packets); err != nil {
		return fmt.Errorf("ledger update: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO usage_samples (ts, path_id, bytes, packets) VALUES (?, ?, ?, ?)`,
		at.Unix(), pathID, bytes, packets); err != nil {
		return fmt.Errorf("usage sample: %w", err)
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

// UsagePoint is one bucket of the usage history.
type UsagePoint struct {
	TS    int64 `json:"ts"`
	Bytes int64 `json:"bytes"`
}

// UsageHistory returns bucketed usage for a path over a window.
func (s *Store) UsageHistory(pathID int, since time.Time, bucketSec int) ([]UsagePoint, error) {
	rows, err := s.db.Query(
		`SELECT (ts / ?) * ?, SUM(bytes) FROM usage_samples
		 WHERE path_id = ? AND ts >= ? GROUP BY 1 ORDER BY 1`,
		bucketSec, bucketSec, pathID, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("usage history: %w", err)
	}
	defer rows.Close()
	var out []UsagePoint
	for rows.Next() {
		var p UsagePoint
		if err := rows.Scan(&p.TS, &p.Bytes); err != nil {
			return nil, err
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
