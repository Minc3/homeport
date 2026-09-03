package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

// A Telegram bot token lives in the URL path, so a redirect used to hand it
// to whoever answered: Go strips a bearer header across hosts and strips
// nothing from a path. Redirects are not followed, and a redirect is reported
// as a failed delivery rather than a success at some other address.
func TestARedirectIsNotFollowed(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer origin.Close()

	cfg := model.NotifyConfig{Kind: "telegram", URL: origin.URL + "/botSECRET/sendMessage", Token: "chat"}
	err := deliver(context.Background(), cfg, "t", "b", PriorityInfo)
	if err == nil {
		t.Fatal("a redirected delivery was reported as a success")
	}
	if hits.Load() != 0 {
		t.Fatal("the redirect target received the request, token in the path and all")
	}
}
