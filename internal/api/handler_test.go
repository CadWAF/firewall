package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/engine"
)

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()

	cfg := &config.Config{
		ConfigDir:  t.TempDir(),
		ListenAddr: "127.0.0.1:9090",
		APIKey:     "test-api-key",
		Iface:      "eth0",
	}
	h := &Handler{
		Cfg:    cfg,
		Engine: engine.NewTestEngine(cfg),
	}
	r := chi.NewRouter()
	Register(r, h)
	return r
}

func TestHealthIsPublic(t *testing.T) {
	handler := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body == "" || body[0] != '{' {
		t.Fatalf("expected JSON body, got %q", body)
	}
}

func TestProtectedRouteRequiresBearerToken(t *testing.T) {
	handler := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ips/whitelist", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestProtectedRouteRejectsInvalidToken(t *testing.T) {
	handler := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ips/whitelist", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestProtectedRouteAcceptsValidToken(t *testing.T) {
	handler := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ips/whitelist", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
}
