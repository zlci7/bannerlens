package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"

	"github.com/zlci7/bannerlens/internal/fingerprint"
	"github.com/zlci7/bannerlens/internal/model"
)

const DefaultMaxBodyBytes int64 = 8 << 20
const DefaultMaxBatch = 10000

// NewHandler serves requests only after the immutable engine has loaded its rules.
func NewHandler(engine *fingerprint.Engine, maxBodyBytes int64, maxBatch int) http.Handler {
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}
	if maxBatch <= 0 {
		maxBatch = DefaultMaxBatch
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodError(w, "GET")
			return
		}
		if engine == nil {
			writeError(w, http.StatusServiceUnavailable, "service not ready")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/fingerprint", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodError(w, "POST")
			return
		}
		if engine == nil {
			writeError(w, http.StatusServiceUnavailable, "service not ready")
			return
		}
		if value := r.Header.Get("Content-Type"); value != "" {
			mediaType, _, err := mime.ParseMediaType(value)
			if err != nil || mediaType != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		defer r.Body.Close()
		// Pointer fields distinguish valid empty banners from missing or null fields.
		var input []*struct {
			IP     *string `json:"ip"`
			Port   *int    `json:"port"`
			Banner *string `json:"banner"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			decodeError(w, err)
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			if err == nil {
				writeError(w, http.StatusBadRequest, "request must contain one JSON array")
				return
			}
			decodeError(w, err)
			return
		}
		if input == nil {
			writeError(w, http.StatusBadRequest, "request must be a JSON array")
			return
		}
		if len(input) > maxBatch {
			writeError(w, http.StatusBadRequest, "batch exceeds record limit")
			return
		}
		records := make([]model.Record, len(input))
		for i, item := range input {
			if item == nil || item.IP == nil || item.Port == nil || item.Banner == nil {
				writeError(w, http.StatusBadRequest, "each record requires ip, port and banner")
				return
			}
			if net.ParseIP(*item.IP) == nil || *item.Port < 1 || *item.Port > 65535 {
				writeError(w, http.StatusBadRequest, "each record requires a valid IP address and port from 1 to 65535")
				return
			}
			records[i] = model.Record{IP: *item.IP, Port: *item.Port, Banner: *item.Banner}
		}
		results := engine.IdentifyBatch(records)
		if results == nil {
			results = []model.Result{}
		}
		writeJSON(w, http.StatusOK, results)
	})
	return mux
}

func decodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds size limit")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid JSON request")
}

func methodError(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
