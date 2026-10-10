package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zlci7/bannerlens/internal/model"
)

func inputFile(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestClientSuccess(t *testing.T) {
	input := inputFile(t, `[{"ip":"1.2.3.4","port":3306,"banner":"J\u0000\u0000\u0000\n8.0.32\u0000"}]`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/fingerprint" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var records []model.Record
		if err := json.NewDecoder(r.Body).Decode(&records); err != nil || len(records) != 1 {
			t.Errorf("invalid request records: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if records[0].Banner != "J\x00\x00\x00\n8.0.32\x00" {
			t.Error("binary banner bytes were changed")
		}
		json.NewEncoder(w).Encode([]model.Result{{IP: records[0].IP, Port: records[0].Port, Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", Confidence: 0.9}})
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := run([]string{"-input", input, "-server", server.URL}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	var results []model.Result
	if err := json.Unmarshal(output.Bytes(), &results); err != nil || len(results) != 1 || results[0].Version != "8.0.32" {
		t.Fatalf("unexpected output: %s (%v)", output.String(), err)
	}
}

func TestClientRejectsResponses(t *testing.T) {
	input := inputFile(t, `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_9.3"}]`)
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"HTTP error", 400, `{"error":"invalid record"}`},
		{"invalid JSON", 200, `{`},
		{"null", 200, `null`},
		{"count", 200, `[]`},
		{"missing field", 200, `[{"ip":"1.2.3.4","port":22,"protocol":"SSH"}]`},
		{"wrong address", 200, `[{"ip":"1.2.3.5","port":22,"protocol":"SSH","product":"","version":"","os_hint":"","confidence":0.5}]`},
		{"invalid confidence", 200, `[{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"","version":"","os_hint":"","confidence":1.1}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			var output bytes.Buffer
			if err := run([]string{"-input", input, "-server", server.URL}, &output, io.Discard); err == nil {
				t.Fatal("expected error")
			}
			if output.Len() != 0 {
				t.Fatal("failed request must not write results")
			}
		})
	}
}

func TestClientInputAndTimeout(t *testing.T) {
	for _, data := range []string{"{", "null", `{"ip":"1.2.3.4"}`} {
		if err := run([]string{"-input", inputFile(t, data)}, io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted invalid input %s", data)
		}
	}
	if err := run([]string{"-input", filepath.Join(t.TempDir(), "missing.json")}, io.Discard, io.Discard); err == nil {
		t.Fatal("accepted missing input")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		io.WriteString(w, "[]")
	}))
	defer server.Close()
	err := run([]string{"-input", inputFile(t, "[]"), "-server", server.URL, "-timeout", "10ms"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("expected request timeout, got %v", err)
	}
}

func TestURLAndSizeLimits(t *testing.T) {
	for _, raw := range []string{"localhost:8080", "ftp://example.com", "http://", "http://user:pass@example.com", "http://example.com/path", "http://example.com?x=1", "http://example.com#fragment"} {
		if _, err := fingerprintURL(raw); err == nil {
			t.Errorf("accepted invalid URL %q", raw)
		}
	}
	if endpoint, err := fingerprintURL("http://server:8080/"); err != nil || endpoint != "http://server:8080/fingerprint" {
		t.Fatalf("unexpected endpoint: %s %v", endpoint, err)
	}
	if _, err := readLimited(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("accepted oversized data")
	}
}
