package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server, *int32, *string, *map[string]any) {
    t.Helper()
    var calls int32
    var auth string
    body := map[string]any{}
    mux := http.NewServeMux()
    mux.HandleFunc("/mint", func(w http.ResponseWriter, r *http.Request) {
        atomic.AddInt32(&calls, 1)
        auth = r.Header.Get("Authorization")
        defer r.Body.Close()
        _ = json.NewDecoder(r.Body).Decode(&body)
        w.WriteHeader(200)
        w.Write([]byte(`{"status":"ok"}`))
    })
    ts := httptest.NewServer(mux)
    s := &Server{
        addr:          ":0",
        secrets:       []string{"dummy"},
        apiBase:       ts.URL,
        repoWhitelist: map[string]struct{}{"owner/repo": {}},
        maintainers:   map[string]struct{}{"alice": {}},
        seen:          map[string]struct{}{},
        nodeToken:     "test-token",
        proposer:      "authority1",
    }
    return s, ts, &calls, &auth, &body
}

func TestPRMerged_MintsWithAuthHeader(t *testing.T) {
    s, ts, calls, auth, body := newTestServer(t)
    defer ts.Close()

    obj := map[string]any{
        "repository": map[string]any{"full_name": "owner/repo"},
        "pull_request": map[string]any{
            "merged": true,
            "state":  "closed",
            "number": 42,
            "user":   map[string]any{"login": "charlie"},
        },
    }
    res := s.processEvent("pull_request", obj, "owner/repo")
    if res != "minted" { t.Fatalf("expected minted, got %s", res) }
    if atomic.LoadInt32(calls) != 1 { t.Fatalf("expected 1 call, got %d", atomic.LoadInt32(calls)) }
    if *auth != "Bearer test-token" { t.Fatalf("missing/incorrect auth header: %s", *auth) }
    if (*body)["proposer"].(string) != "authority1" { t.Fatalf("bad proposer: %v", (*body)["proposer"]) }
    if (*body)["to"].(string) != "charlie" { t.Fatalf("bad to: %v", (*body)["to"]) }
    if (*body)["amount"].(float64) != 100 { t.Fatalf("bad amount: %v", (*body)["amount"]) }
}

func TestDocsPR_MintsReducedReward(t *testing.T) {
    s, ts, calls, _, body := newTestServer(t)
    defer ts.Close()
    obj := map[string]any{
        "repository": map[string]any{"full_name": "owner/repo"},
        "pull_request": map[string]any{
            "merged": true,
            "state":  "closed",
            "number": 7,
            "user":   map[string]any{"login": "dana"},
            "labels": []any{ map[string]any{"name": "docs"} },
        },
    }
    res := s.processEvent("pull_request", obj, "owner/repo")
    if res != "minted" { t.Fatalf("expected minted, got %s", res) }
    if atomic.LoadInt32(calls) != 1 { t.Fatalf("expected 1 call, got %d", atomic.LoadInt32(calls)) }
    if (*body)["amount"].(float64) != 25 { t.Fatalf("bad amount for docs PR: %v", (*body)["amount"]) }
}

func TestPushMain_NonMaintainer_Rewarded(t *testing.T) {
    s, ts, calls, _, body := newTestServer(t)
    defer ts.Close()
    obj := map[string]any{
        "repository": map[string]any{"full_name": "owner/repo"},
        "ref": "refs/heads/main",
        "commits": []any{
            map[string]any{
                "id": "abc123",
                "author": map[string]any{"username": "eve"},
                "added": []any{"file.go"},
                "modified": []any{},
            },
        },
    }
    res := s.processEvent("push", obj, "owner/repo")
    if res != "minted" { t.Fatalf("expected minted, got %s", res) }
    if atomic.LoadInt32(calls) != 1 { t.Fatalf("expected 1 call, got %d", atomic.LoadInt32(calls)) }
    if (*body)["amount"].(float64) != 50 { t.Fatalf("bad amount for push: %v", (*body)["amount"]) }
}
