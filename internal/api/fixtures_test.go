package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/zlci7/bannerlens/internal/model"
)

func TestSampleBatchOverHTTP(t *testing.T) {
	input, err := os.ReadFile("../../testdata/banners.json")
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile("../../testdata/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(testHandler(t, 0, 0))
	defer server.Close()
	response, err := server.Client().Post(server.URL+"/fingerprint", "application/json", bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("HTTP status: %d", response.StatusCode)
	}
	var got, want []model.Result
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(expected, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sample batch mismatch:\ngot: %+v\nwant: %+v", got, want)
	}
}
