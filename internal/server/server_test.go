package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"banner-fingerprint/internal/fingerprint"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	path, err := fingerprint.ResolveRulesPath([]string{"../../rules/rules.json", "rules/rules.json"})
	if err != nil {
		t.Fatalf("resolve rules path: %v", err)
	}
	rules, err := fingerprint.LoadRulesFile(path)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	eng, err := fingerprint.NewEngine(rules)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return New(Config{Engine: eng, Version: "test"})
}

func TestHealth(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"status":"ok"`) {
		t.Fatalf("body = %q", rr.Body.String())
	}
}

func TestFingerprint(t *testing.T) {
	s := testServer(t)
	body := `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},{"ip":"1.2.3.99","port":1,"banner":"garbage"}]`
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var res []fingerprint.Result
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("len = %d, want 2", len(res))
	}
	if res[0].Protocol != "SSH" || res[0].Product != "OpenSSH" || res[0].Version != "8.9p1" || res[0].OsHint != "Ubuntu" {
		t.Fatalf("res[0] = %+v", res[0])
	}
	if res[1].Protocol != "unknown" {
		t.Fatalf("res[1].protocol = %q, want unknown", res[1].Protocol)
	}
}

func TestFingerprintInvalidJSON(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(`{"bad`))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestFingerprintWrongMethod(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/fingerprint", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}
