package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/go-retryablehttp"
)

type Server struct {
	addr         string
	secrets      []string
	apiBase      string
	repoWhitelist map[string]struct{}
	httpServer   *http.Server
	maintainers  map[string]struct{}
	seen         map[string]struct{}
	mu           sync.Mutex
	nodeToken    string
	proposer     string
}

type MintRequest struct {
	Proposer string `json:"proposer"`
	To       string `json:"to"`
	Amount   uint64 `json:"amount"`
}

func New(addr, secret, api string, repos []string) (*Server, error) {
	if secret == "" { return nil, errors.New("missing secret") }
	wl := map[string]struct{}{}
	for _, r := range repos { if strings.TrimSpace(r) != "" { wl[strings.TrimSpace(r)] = struct{}{} } }
	// Maintainers from env (comma-separated usernames)
	maint := map[string]struct{}{}
	if v := os.Getenv("MAINTAINERS"); v != "" {
		for _, m := range strings.Split(v, ",") {
			m = strings.TrimSpace(m)
			if m != "" { maint[m] = struct{}{} }
		}
	}
	r := gin.New()
	r.Use(gin.Recovery())
	// Allow multiple secrets for rotation (comma-separated)
	secrets := splitList(secret)
	if len(secrets) == 0 { secrets = []string{secret} }
	nodeToken := os.Getenv("ORACLE_NODE_TOKEN")
	proposer := os.Getenv("ORACLE_PROPOSER")
	if proposer == "" { proposer = "authority1" }
	s := &Server{addr: addr, secrets: secrets, apiBase: strings.TrimRight(api, "/"), repoWhitelist: wl, maintainers: maint, seen: map[string]struct{}{}, nodeToken: nodeToken, proposer: proposer }
	r.POST("/webhook", s.handleWebhook)
	r.GET("/healthz", func(c *gin.Context){ c.String(200, "ok") })
	s.httpServer = &http.Server{ Addr: addr, Handler: r }
	return s, nil
}

func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) verifySignature(sigHeader string, body []byte) bool {
	// GitHub signatures: sha256=hex
	const prefix = "sha256="
	if !strings.HasPrefix(sigHeader, prefix) { return false }
	hexSig := strings.TrimPrefix(sigHeader, prefix)
	got, err := hex.DecodeString(hexSig)
	if err != nil { return false }
	for _, sec := range s.secrets {
		mac := hmac.New(sha256.New, []byte(strings.TrimSpace(sec)))
		mac.Write(body)
		exp := mac.Sum(nil)
		if hmac.Equal(exp, got) { return true }
	}
	return false
}

func (s *Server) handleWebhook(c *gin.Context) {
	// Verify signature
	sig := c.GetHeader("X-Hub-Signature-256")
	payload, err := io.ReadAll(c.Request.Body)
	if err != nil { c.String(http.StatusBadRequest, "read error"); return }
	if !s.verifySignature(sig, payload) { c.String(http.StatusUnauthorized, "bad signature"); return }

	// Parse event type and payload minimally
	event := c.GetHeader("X-GitHub-Event")
	var obj map[string]any
	if err := json.Unmarshal(payload, &obj); err != nil { c.String(http.StatusBadRequest, "json error"); return }

	// Determine repository full_name
	repoFull := ""
	if repo, ok := obj["repository"].(map[string]any); ok {
		if fn, ok := repo["full_name"].(string); ok { repoFull = fn }
	}
	if len(s.repoWhitelist) > 0 {
		if _, ok := s.repoWhitelist[repoFull]; !ok { c.String(http.StatusOK, "ignored repo"); return }
	}

	// Delegate to actions engine
	res := s.processEvent(event, obj, repoFull)
	c.String(http.StatusOK, res)
}

// Helpers used by actions.go
func (s *Server) isMaintainer(user string) bool {
	_, ok := s.maintainers[user]
	return ok
}

func (s *Server) markSeen(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.seen[key]; exists { return false }
	if len(s.seen) > 5000 { s.seen = map[string]struct{}{} }
	s.seen[key] = struct{}{}
	return true
}

func (s *Server) mintFor(githubUser string, amount uint64) error {
	// Wallet mapping MVP: username->same string; in real world resolve to wallet address
	addr := githubUser
	mr := MintRequest{ Proposer: s.proposer, To: addr, Amount: amount }
	b, _ := json.Marshal(mr)

	client := retryablehttp.NewClient()
	client.RetryWaitMin = 500 * time.Millisecond
	client.RetryWaitMax = 2 * time.Second
	client.RetryMax = 4

	req, err := retryablehttp.NewRequest(http.MethodPost, s.apiBase+"/mint", b)
	if err != nil { return err }
	req.Header.Set("Content-Type", "application/json")
	if s.nodeToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.nodeToken)
	}
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("mint error: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

// splitList splits a comma-separated list into trimmed non-empty elements.
func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" { out = append(out, p) }
	}
	return out
}
