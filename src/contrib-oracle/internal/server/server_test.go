package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestVerifySignature_Valid(t *testing.T) {
	s, err := New(":0", "secret", "http://localhost:8080", nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !s.verifySignature(sig, body) {
		t.Fatal("expected valid signature")
	}
}

func TestWebhook_IgnoredRepo(t *testing.T) {
	s, err := New(":0", "secret", "http://localhost:8080", []string{"whitelisted/repo"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// gin engine for testing this handler
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/webhook", s.handleWebhook)

	payload := `{"repository": {"full_name":"other/repo"}}`
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(payload))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ignored") {
		t.Fatalf("expected ignored response, got %q", w.Body.String())
	}
}
