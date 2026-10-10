package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/zlci7/bannerlens/internal/model"
)

const maxInputBytes int64 = 8 << 20
const maxResponseBytes int64 = 16 << 20

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "testdata/banners.json", "JSON input file")
	server := flags.String("server", "http://localhost:8080", "server base URL")
	timeout := flags.Duration("timeout", 15*time.Second, "HTTP request timeout")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	endpoint, err := fingerprintURL(*server)
	if err != nil {
		return err
	}
	file, err := os.Open(*input)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer file.Close()
	data, err := readLimited(file, maxInputBytes)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	var records []model.Record
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("input must be a JSON array: %w", err)
	}
	if records == nil {
		return errors.New("input must be a JSON array, not null")
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: *timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer response.Body.Close()
	body, err := readLimited(response.Body, maxResponseBytes)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(body))
		if len(message) > 1024 {
			message = message[:1024]
		}
		return fmt.Errorf("server returned HTTP %d: %s", response.StatusCode, message)
	}
	results, err := validateResults(body, records)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("write results: %w", err)
	}
	return nil
}

func fingerprintURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("server must be an http or https base URL with a host and no credentials, path, query or fragment")
	}
	u.Path = "/fingerprint"
	return u.String(), nil
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("size exceeds %d bytes", limit)
	}
	return data, nil
}

func validateResults(data []byte, records []model.Record) ([]model.Result, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
		return nil, errors.New("server response must be a JSON array")
	}
	if len(raw) != len(records) {
		return nil, errors.New("server response count differs from input")
	}
	results := make([]model.Result, len(raw))
	for i, item := range raw {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(item, &fields); err != nil {
			return nil, fmt.Errorf("invalid result at index %d", i)
		}
		for _, key := range []string{"ip", "port", "protocol", "product", "version", "os_hint", "confidence"} {
			value, ok := fields[key]
			if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return nil, fmt.Errorf("result %d lacks required field %s", i, key)
			}
		}
		if err := json.Unmarshal(item, &results[i]); err != nil {
			return nil, fmt.Errorf("decode result %d: %w", i, err)
		}
		r := results[i]
		if r.IP != records[i].IP || r.Port != records[i].Port || r.Protocol == "" || r.Confidence < 0 || r.Confidence > 1 {
			return nil, fmt.Errorf("result %d has invalid fields or address order", i)
		}
	}
	return results, nil
}
