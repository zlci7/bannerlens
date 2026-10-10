package fingerprint

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/zlci7/bannerlens/internal/model"
)

func loadDefault(t *testing.T) *Engine {
	t.Helper()
	e, err := Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestIdentify(t *testing.T) {
	e := loadDefault(t)
	cases := []struct {
		banner, protocol, product, version, os string
		confidence                             float64
	}{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "SSH", "OpenSSH", "8.9p1", "Ubuntu", .95},
		{"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html", "HTTP", "nginx", "1.24.0", "", .9},
		{"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57", "HTTP", "Apache", "2.4.57", "", .9},
		{"J\x00\x00\x00\n8.0.32\x00", "MySQL", "MySQL", "8.0.32", "", .9},
		{"-ERR wrong number of arguments for 'get' command", "Redis", "Redis", "", "", .7},
		{"220 ProFTPD 1.3.7 Server (ProFTPD)", "FTP", "ProFTPD", "1.3.7", "", .9},
		{"HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51", "HTTP", "Jetty", "9.4.51", "", .85},
		{"SSH-2.0-OpenSSH_9.3 Debian-1", "SSH", "OpenSSH", "9.3", "Debian", .95},
		{"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)", "HTTP", "nginx", "1.18.0", "Ubuntu", .9},
		{"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)", "HTTP", "Apache", "2.4.41", "Ubuntu", .9},
		{"J\x00\x00\x00\n5.7.42\x00", "MySQL", "MySQL", "5.7.42", "", .9},
		{"+PONG", "Redis", "Redis", "", "", .7},
		{"220 (vsFTPd 3.0.5)", "FTP", "vsFTPd", "3.0.5", "", .9},
		{"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3", "HTTP", "nginx", "1.25.3", "", .9},
		{"SSH-1.99-OpenSSH_4.3", "SSH", "OpenSSH", "4.3", "", .95},
		{"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1", "unknown", "", "", "", 0},
		{"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0", "HTTP", "Microsoft-IIS", "10.0", "", .9},
		{"-NOAUTH Authentication required.", "Redis", "Redis", "", "", .7},
		{"220 Welcome to Pure-FTPd", "FTP", "Pure-FTPd", "", "", .7},
		{"QUIT\r\n", "unknown", "", "", "", 0},
		{"HTTP/1.1 200 OK\r\nserver: Jetty(12.0.16)", "HTTP", "Jetty", "12.0.16", "", .85},
		{"# Server\r\nredis_version:7.4.2\r\nredis_mode:standalone\r\n", "Redis", "Redis", "7.4.2", "", .95},
		{"J\x00\x00\x00\n5.5.5-10.11.8-MariaDB-0ubuntu0.24.04.1\x00", "MySQL", "MariaDB", "10.11.8", "", .9},
		{"HTTP/2 200\r\nServer: other-server", "HTTP", "", "", "", .8},
		{"220 Welcome to FTP service\r\n", "FTP", "", "", "", .7},
		{"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nServer: nginx/1.2.3\r\nUbuntu", "HTTP", "", "", "", .8},
		{"Server: nginx/1.24.0", "unknown", "", "", "", 0},
		{"220 mail.example ESMTP Postfix\r\n", "unknown", "", "", "", 0},
		{"The software is OpenSSH_9.9p2", "unknown", "", "", "", 0},
		{"nginx/1.24.0", "unknown", "", "", "", 0},
		{"+PONG arbitrary text", "unknown", "", "", "", 0},
		{"J\x00\x00\x01\n8.0.32\x00", "unknown", "", "", "", 0},
		{"J\x00\x00\x00\n8.0.32", "unknown", "", "", "", 0},
		{"", "unknown", "", "", "", 0},
	}
	for _, c := range cases {
		t.Run(c.banner, func(t *testing.T) {
			// Deliberately unrelated port: recognition must follow the banner.
			got := e.Identify(model.Record{IP: "192.0.2.1", Port: 12345, Banner: c.banner})
			want := model.Result{IP: "192.0.2.1", Port: 12345, Protocol: c.protocol, Product: c.product, Version: c.version, OSHint: c.os, Confidence: c.confidence}
			if got != want {
				t.Fatalf("got %+v; want %+v", got, want)
			}
		})
	}
}

func TestBatch(t *testing.T) {
	e := loadDefault(t)
	got := e.IdentifyBatch([]model.Record{{IP: "a", Port: 1, Banner: "+PONG"}, {IP: "b", Port: 22, Banner: "unknown"}})
	if len(got) != 2 || got[0].IP != "a" || got[1].IP != "b" || got[1].Protocol != "unknown" {
		t.Fatalf("%+v", got)
	}
	b, err := json.Marshal(e.IdentifyBatch(nil))
	if err != nil || string(b) != "[]" {
		t.Fatalf("empty batch: %s %v", b, err)
	}
}

func TestMySQLBinaryJSON(t *testing.T) {
	e := loadDefault(t)
	for _, header := range [][]byte{{0xc8, 0, 0, 0, 10}, {0x80, 1, 0, 0, 10}, {0x80, 0x80, 0, 0, 10}} {
		raw := append(append([]byte{}, header...), []byte("8.4.3-commercial\x00")...)
		var latin []rune
		for _, b := range raw {
			latin = append(latin, rune(b))
		}
		for _, banner := range []string{string(raw), string(latin)} {
			got := e.Identify(model.Record{Banner: banner})
			if got.Protocol != "MySQL" || got.Version != "8.4.3" {
				t.Fatalf("header %x: %+v", header, got)
			}
		}
	}
	// Decode the same representation accepted by the API's JSON decoder.
	var record model.Record
	if err := json.Unmarshal([]byte(`{"banner":"\u00c8\u0000\u0000\u0000\n8.4.3\u0000"}`), &record); err != nil {
		t.Fatal(err)
	}
	if got := e.Identify(record); got.Version != "8.4.3" {
		t.Fatal(got)
	}
	for _, banner := range []string{"\x03\x00\x00\x00\n8.4.3\x00", "\xc8\x00\x00\x00\n8.4.3", "\xc8\x00\x00\x00\nhello\x00"} {
		if got := e.Identify(model.Record{Banner: banner}); got.Protocol != "unknown" {
			t.Fatal(got)
		}
	}
}

func TestPortsDoNotCreateEvidence(t *testing.T) {
	e := loadDefault(t)
	for _, port := range []int{21, 22, 80, 443, 3306, 6379, 8080} {
		if got := e.Identify(model.Record{Port: port, Banner: "unrecognized service"}); got.Protocol != "unknown" {
			t.Fatal(got)
		}
	}
}

func TestHTTPBodyCannotSelectProtocol(t *testing.T) {
	e := loadDefault(t)
	for _, body := range []string{
		"SSH-2.0-OpenSSH_9.9p2 Ubuntu-3",
		"redis_version:7.4.2\r\n",
		"220 ProFTPD 1.3.7 Server (ProFTPD)",
		"220 Welcome to Pure-FTPd",
		"Server: nginx/1.24.0\r\nWindows",
	} {
		for _, header := range []string{"HTTP/1.1 200 OK\r\nContent-Type: text/plain", "HTTP/1.1 200 OK\r\nServer: nginx/1.27.4"} {
			got := e.Identify(model.Record{Banner: header + "\r\n\r\n" + body})
			if got.Protocol != "HTTP" || got.OSHint != "" {
				t.Fatalf("body %q: %+v", body, got)
			}
			if header == "HTTP/1.1 200 OK\r\nContent-Type: text/plain" && got.Product != "" {
				t.Fatalf("body selected product: %+v", got)
			}
			if header == "HTTP/1.1 200 OK\r\nServer: nginx/1.27.4" && (got.Product != "nginx" || got.Version != "1.27.4") {
				t.Fatalf("body overrode header: %+v", got)
			}
		}
	}
}

func TestLoadValidationAndCustomRules(t *testing.T) {
	for _, data := range []string{
		`{}`, `{ "rules": [] }`, `{} {}`, `{"rules":[],"typo":1}`,
		`{"rules":[{"id":"x","source":"banner","pattern":"[","protocol":"SSH","confidence":0.9}]}`,
		`{"rules":[{"id":"x","source":"banner","pattern":"x","protocol":"SSH","version_group":1,"confidence":0.9}]}`,
		`{"rules":[{"id":"x","source":"banner","pattern":"x","protocol":"SSH","confidence":1.1}]}`,
		`{"rules":[{"id":"x","source":"typo","pattern":"x","protocol":"SSH","confidence":0.9}]}`,
		`{"rules":[{"id":"x","source":"banner","pattern":".*","protocol":"SSH","confidence":0.9}]}`,
		`{"rules":[{"id":"x","source":"banner","pattern":"x","protocol":"SSH","confidence":0.9},{"id":"x","source":"banner","pattern":"y","protocol":"SSH","confidence":0.9}]}`,
		`{"rules":[{"id":"x","source":"banner","pattern":"x","protocol":"SSH","confidence":0.9}],"os_rules":[{"pattern":"[","hint":"Linux"}]}`,
	} {
		path := filepath.Join(t.TempDir(), "rules.json")
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("accepted invalid config: %s", data)
		}
	}
	path := filepath.Join(t.TempDir(), "rules.json")
	data := `{"rules":[{"id":"generic","priority":1,"source":"banner","pattern":"CUSTOM","protocol":"Custom","confidence":0.5},{"id":"specific","priority":2,"source":"banner","pattern":"CUSTOM/([0-9.]+)","protocol":"Custom","product":"CustomApp","version_group":1,"confidence":0.99}]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	e, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := e.Identify(model.Record{Banner: "CUSTOM/2.0"})
	if got.Product != "CustomApp" || got.Version != "2.0" || got.Confidence != .99 {
		t.Fatalf("%+v", got)
	}
}

func TestTruncatedAndRandomData(t *testing.T) {
	e := loadDefault(t)
	for _, banner := range []string{"J\x00\x00\x00\n8.0.32\x00", "SSH-2.0-OpenSSH_9.9p2", "HTTP/1.1 200 OK\r\nServer: nginx/1.27.4"} {
		for i := 0; i < len(banner); i++ {
			e.Identify(model.Record{Banner: banner[:i]})
		}
	}
	r := rand.New(rand.NewSource(42))
	for i := 0; i < 1000; i++ {
		b := make([]byte, r.Intn(256))
		r.Read(b)
		got := e.Identify(model.Record{Banner: string(b)})
		if got.Confidence < 0 || got.Confidence > 1 {
			t.Fatal(got)
		}
	}
}

func FuzzIdentify(f *testing.F) {
	e, err := Load("../../rules/fingerprints.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add("J\x00\x00\x00\n8.0.32\x00")
	f.Add("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0")
	f.Fuzz(func(t *testing.T, banner string) {
		got := e.Identify(model.Record{Banner: banner})
		if got.Confidence < 0 || got.Confidence > 1 || got.Protocol == "" {
			t.Fatal(got)
		}
	})
}
