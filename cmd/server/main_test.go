package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbe(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable, http.StatusFound} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" {
				t.Errorf("probe path %s", r.URL.Path)
			}
			w.WriteHeader(status)
		}))
		err := probe(server.URL + "/health")
		server.Close()
		if (err == nil) != (status == http.StatusOK) {
			t.Errorf("status %d, error %v", status, err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	address := server.URL
	server.Close()
	if probe(address) == nil {
		t.Fatal("probe succeeded on closed server")
	}
}
