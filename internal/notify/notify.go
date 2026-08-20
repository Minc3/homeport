// Package notify delivers alerts about failovers, path failures and quota
// exhaustion.
//
// This matters more than it looks. Quota exhaustion parks the system waiting
// for a human to approve using an over-quota path; without a notification
// channel that approval only happens when somebody happens to open the portal.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quinlan102/homeport/internal/model"
)

// Priority ranks an alert.
type Priority string

// Alert priorities.
const (
	PriorityInfo    Priority = "info"
	PriorityWarning Priority = "warning"
	PriorityUrgent  Priority = "urgent"
)

// Notifier sends alerts according to the current configuration.
type Notifier struct {
	log *slog.Logger

	mu   sync.Mutex
	cfg  model.NotifyConfig
	last map[string]time.Time
}

// New builds a notifier.
func New(log *slog.Logger) *Notifier {
	return &Notifier{log: log, last: map[string]time.Time{}}
}

// SetConfig updates the notifier's settings from the portal.
func (n *Notifier) SetConfig(cfg model.NotifyConfig) {
	n.mu.Lock()
	n.cfg = cfg
	n.mu.Unlock()
}

// Event kinds map onto the per-kind toggles in the configuration.
const (
	KindSwitch   = "switch"
	KindPathDown = "path_down"
	KindQuota    = "quota"
	KindHeld     = "held"
)

// Send delivers an alert, rate-limited per dedupe key so a flapping path
// cannot turn into a notification storm.
func (n *Notifier) Send(ctx context.Context, kind, dedupeKey, title, body string, prio Priority) {
	n.mu.Lock()
	cfg := n.cfg
	if !cfg.Enabled || !enabledFor(cfg, kind) {
		n.mu.Unlock()
		return
	}
	// Urgent alerts repeat every 15 minutes; everything else every 5.
	cooldown := 5 * time.Minute
	if prio == PriorityUrgent {
		cooldown = 15 * time.Minute
	}
	if t, ok := n.last[dedupeKey]; ok && time.Since(t) < cooldown {
		n.mu.Unlock()
		return
	}
	n.last[dedupeKey] = time.Now()
	n.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if err := deliver(ctx, cfg, title, body, prio); err != nil {
			n.log.Warn("notification failed", "kind", kind, "err", err)
		}
	}()
}

func enabledFor(cfg model.NotifyConfig, kind string) bool {
	switch kind {
	case KindSwitch:
		return cfg.OnSwitch
	case KindPathDown:
		return cfg.OnPathDown
	case KindQuota:
		return cfg.OnQuota
	case KindHeld:
		return cfg.OnHeld
	}
	return true
}

func deliver(ctx context.Context, cfg model.NotifyConfig, title, body string, prio Priority) error {
	if cfg.URL == "" {
		return fmt.Errorf("no notification URL configured")
	}
	switch strings.ToLower(cfg.Kind) {
	case "ntfy":
		return sendNtfy(ctx, cfg, title, body, prio)
	case "telegram":
		return sendTelegram(ctx, cfg, title, body)
	default:
		return sendWebhook(ctx, cfg, title, body, prio)
	}
}

func sendNtfy(ctx context.Context, cfg model.NotifyConfig, title, body string, prio Priority) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", title)
	switch prio {
	case PriorityUrgent:
		req.Header.Set("Priority", "urgent")
		req.Header.Set("Tags", "rotating_light")
	case PriorityWarning:
		req.Header.Set("Priority", "high")
		req.Header.Set("Tags", "warning")
	default:
		req.Header.Set("Tags", "satellite")
	}
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	return do(req)
}

func sendTelegram(ctx context.Context, cfg model.NotifyConfig, title, body string) error {
	payload := map[string]string{
		"chat_id": cfg.Token,
		"text":    title + "\n" + body,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return do(req)
}

// sendWebhook posts a Slack/Discord-compatible JSON body.
func sendWebhook(ctx context.Context, cfg model.NotifyConfig, title, body string, prio Priority) error {
	payload := map[string]any{
		"content":  fmt.Sprintf("**%s**\n%s", title, body),
		"text":     fmt.Sprintf("*%s*\n%s", title, body),
		"priority": string(prio),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	return do(req)
}

func do(req *http.Request) error {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notification endpoint returned %s", resp.Status)
	}
	return nil
}
