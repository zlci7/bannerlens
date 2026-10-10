package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zlci7/bannerlens/internal/fingerprint"
	"github.com/zlci7/bannerlens/internal/model"
)

func testHandler(t *testing.T, limit int64, batch int) http.Handler {
	t.Helper()
	engine, err := fingerprint.Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	return NewHandler(engine, limit, batch)
}

func request(handler http.Handler, method, path, body, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestRequestValidation(t *testing.T) {
	handler := testHandler(t, 0, 0)
	tests := []struct {
		name, body string
		status     int
	}{
		{"empty array", `[]`, 200},
		{"empty banner", `[{"ip":"::1","port":1,"banner":""}]`, 200},
		{"highest port", `[{"ip":"127.0.0.1","port":65535,"banner":"QUIT"}]`, 200},
		{"null array", `null`, 400},
		{"object", `{}`, 400},
		{"empty body", ``, 400},
		{"broken JSON", `[`, 400},
		{"extra JSON", `[] []`, 400},
		{"trailing garbage", `[] x`, 400},
		{"null item", `[null]`, 400},
		{"missing field", `[{"ip":"127.0.0.1","port":22}]`, 400},
		{"null banner", `[{"ip":"127.0.0.1","port":22,"banner":null}]`, 400},
		{"invalid ip", `[{"ip":"host.example","port":22,"banner":"SSH"}]`, 400},
		{"zero port", `[{"ip":"127.0.0.1","port":0,"banner":""}]`, 400},
		{"excess port", `[{"ip":"127.0.0.1","port":65536,"banner":""}]`, 400},
		{"string port", `[{"ip":"127.0.0.1","port":"22","banner":""}]`, 400},
		{"fraction port", `[{"ip":"127.0.0.1","port":22.5,"banner":""}]`, 400},
		{"wrong banner", `[{"ip":"127.0.0.1","port":22,"banner":42}]`, 400},
		{"unknown field", `[{"ip":"127.0.0.1","port":22,"banner":"","extra":1}]`, 400},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := request(handler, "POST", "/fingerprint", test.body, "application/json")
			if response.Code != test.status {
				t.Fatalf("status %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			if !json.Valid(response.Body.Bytes()) {
				t.Fatalf("invalid JSON response: %s", response.Body.String())
			}
		})
	}
}

func TestLimitsAndHTTPContract(t *testing.T) {
	handler := testHandler(t, 80, 1)
	tests := []struct {
		name, method, path, body, contentType string
		status                                int
	}{
		{"healthy", "GET", "/health", "", "", 200},
		{"health method", "POST", "/health", "", "", 405},
		{"fingerprint method", "GET", "/fingerprint", "", "", 405},
		{"missing route", "GET", "/missing", "", "", 404},
		{"unsupported content", "POST", "/fingerprint", `[]`, "text/plain", 415},
		{"bad content header", "POST", "/fingerprint", `[]`, "application/json;=", 415},
		{"UTF8 JSON", "POST", "/fingerprint", `[]`, "application/json; charset=utf-8", 200},
		{"batch limit", "POST", "/fingerprint", `[{"ip":"::1","port":22,"banner":""},{"ip":"::1","port":22,"banner":""}]`, "application/json", 400},
		{"body limit", "POST", "/fingerprint", `[{"ip":"::1","port":22,"banner":"` + strings.Repeat("X", 80) + `"}]`, "application/json", 413},
		{"trailing body limit", "POST", "/fingerprint", `[]` + strings.Repeat(" ", 80), "application/json", 413},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := request(handler, test.method, test.path, test.body, test.contentType)
			if response.Code != test.status {
				t.Fatalf("status %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			if test.status == 405 && response.Header().Get("Allow") == "" {
				t.Fatal("missing Allow")
			}
		})
	}
	if r := request(NewHandler(nil, 0, 0), "GET", "/health", "", ""); r.Code != 503 {
		t.Fatalf("nil engine health: %d", r.Code)
	}
}

func TestResultsAndConcurrency(t *testing.T) {
	handler := testHandler(t, 0, 0)
	payload := `[{"ip":"127.0.0.1","port":2222,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},{"ip":"::1","port":22,"banner":"QUIT\r\n"}]`
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			response := request(handler, "POST", "/fingerprint", payload, "application/json")
			var results []model.Result
			if err := json.Unmarshal(response.Body.Bytes(), &results); err != nil {
				t.Error(err)
				return
			}
			if response.Code != 200 || len(results) != 2 {
				t.Errorf("unexpected response %d: %s", response.Code, response.Body.String())
				return
			}
			if results[0].IP != "127.0.0.1" || results[0].Port != 2222 || results[0].Protocol != "SSH" || results[0].Version != "8.9p1" {
				t.Error(fmt.Sprintf("first result: %+v", results[0]))
			}
			if results[1].Protocol != "unknown" {
				t.Errorf("unknown result: %+v", results[1])
			}
		}()
	}
	workers.Wait()
	response := request(handler, "POST", "/fingerprint", "[]", "application/json")
	if strings.TrimSpace(response.Body.String()) != "[]" {
		t.Fatalf("empty results: %s", response.Body.String())
	}
}
