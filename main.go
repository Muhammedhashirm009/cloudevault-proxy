package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	authToken     string
	activeStreams  int64
	totalServed   int64
	startTime     = time.Now()
)

type errorResponse struct {
	Error       string `json:"error"`
	Code        string `json:"code"`
	DriveDetail string `json:"driveDetail,omitempty"`
}

func main() {
	authToken = os.Getenv("STREAM_AUTH_TOKEN")
	if authToken == "" {
		log.Fatal("[CloudVault] FATAL: STREAM_AUTH_TOKEN is not set.")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/stream/", handleStream)
	mux.HandleFunc("/", handleNotFound)

	// Wrap with CORS
	handler := corsMiddleware(mux)

	log.Printf("[CloudVault Proxy v3.0-go] Listening on port %s", port)
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // No write timeout for streaming
		IdleTimeout:  120 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("[CloudVault] Server error: %v", err)
	}
}

// ── CORS Middleware ───────────────────────────────────────────────────────────

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Range")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Range, Content-Length, Accept-Ranges, Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── Health Endpoint ──────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	resp := map[string]interface{}{
		"status":        "ok",
		"version":       "3.0-go",
		"uptime":        int(time.Since(startTime).Seconds()),
		"activeStreams":  atomic.LoadInt64(&activeStreams),
		"totalServed":   atomic.LoadInt64(&totalServed),
		"goroutines":    runtime.NumGoroutine(),
		"memoryMB": map[string]interface{}{
			"alloc":    m.Alloc / 1048576,
			"sys":      m.Sys / 1048576,
			"numGC":    m.NumGC,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ── Stream Endpoint ──────────────────────────────────────────────────────────

func handleStream(w http.ResponseWriter, r *http.Request) {
	// Extract fileId from /stream/{fileId}
	path := strings.TrimPrefix(r.URL.Path, "/stream/")
	fileId := strings.TrimSuffix(path, "/")
	if fileId == "" {
		writeError(w, http.StatusBadRequest, "Missing file ID.", "MISSING_FILE_ID", "")
		return
	}

	query := r.URL.Query()
	token := query.Get("token")
	expires := query.Get("expires")
	at := query.Get("at")

	reqId := fmt.Sprintf("%s-%d", fileId[:min(8, len(fileId))], time.Now().UnixMilli()%100000)

	// ── Auth checks ──────────────────────────────────────────────────────────
	if !verifyToken(fileId, token, expires) {
		now := time.Now().Unix()
		exp, _ := strconv.ParseInt(expires, 10, 64)
		log.Printf("[%s] AUTH FAIL: expires=%s now=%d diff=%ds fileId=%s", reqId, expires, now, exp-now, fileId)
		writeError(w, http.StatusForbidden, "Invalid or expired stream token.", "TOKEN_EXPIRED", "")
		return
	}

	if at == "" {
		log.Printf("[%s] AUTH FAIL: missing Google access token", reqId)
		writeError(w, http.StatusBadRequest, "Missing Google access token (at).", "MISSING_AT", "")
		return
	}

	// Token preview for logs (first/last 4 chars)
	atPreview := "****"
	if len(at) > 8 {
		atPreview = at[:4] + "..." + at[len(at)-4:]
	}
	exp, _ := strconv.ParseInt(expires, 10, 64)
	expiresIn := exp - time.Now().Unix()

	active := atomic.AddInt64(&activeStreams, 1)
	atomic.AddInt64(&totalServed, 1)
	log.Printf("[%s] START file=%s at=%s hmacExpiresIn=%ds range=%s active=%d",
		reqId, fileId, atPreview, expiresIn, r.Header.Get("Range"), active)

	defer func() {
		curr := atomic.AddInt64(&activeStreams, -1)
		log.Printf("[%s] END active=%d", reqId, curr)
	}()

	// ── Build Google Drive request ───────────────────────────────────────────
	driveURL := fmt.Sprintf("https://www.googleapis.com/drive/v3/files/%s?alt=media", fileId)

	driveReq, err := http.NewRequestWithContext(r.Context(), "GET", driveURL, nil)
	if err != nil {
		log.Printf("[%s] ERROR creating request: %v", reqId, err)
		writeError(w, http.StatusInternalServerError, "Internal error.", "INTERNAL", "")
		return
	}

	driveReq.Header.Set("Authorization", "Bearer "+at)
	driveReq.Header.Set("User-Agent", "CloudVault/3.0-go")

	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		driveReq.Header.Set("Range", rangeHeader)
	}

	// ── Execute Google Drive request ─────────────────────────────────────────
	// Use a transport that doesn't pool connections (prevents socket accumulation)
	transport := &http.Transport{
		DisableKeepAlives: true,
		MaxIdleConns:      0,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow redirects but carry the auth header
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			req.Header.Set("Authorization", "Bearer "+at)
			return nil
		},
	}

	resp, err := client.Do(driveReq)
	if err != nil {
		// Check if client disconnected (context cancelled)
		if r.Context().Err() != nil {
			log.Printf("[%s] CLIENT DISCONNECT before Drive response", reqId)
			return
		}
		log.Printf("[%s] DRIVE CONNECT ERROR: %v", reqId, err)
		if strings.Contains(err.Error(), "timeout") {
			writeError(w, http.StatusGatewayTimeout, "Google Drive connection timed out.", "TIMEOUT", "")
		} else {
			writeError(w, http.StatusBadGateway, "Connection to Google Drive failed.", "CONNECT_ERROR", "")
		}
		return
	}
	defer resp.Body.Close()

	// ── Handle Drive errors ──────────────────────────────────────────────────
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		driveDetail := parseDriveError(body)

		var errorMsg, errorCode string
		switch resp.StatusCode {
		case 401:
			errorMsg = "Google access token expired. Player will auto-refresh."
			errorCode = "GOOGLE_TOKEN_EXPIRED"
		case 403:
			errorMsg = "Google Drive access denied. Token may be expired."
			errorCode = "GOOGLE_TOKEN_EXPIRED"
		case 404:
			errorMsg = fmt.Sprintf("File %s not found in Google Drive.", fileId)
			errorCode = "FILE_NOT_FOUND"
		case 429:
			errorMsg = "Google Drive rate limit hit. Try again in a moment."
			errorCode = "RATE_LIMITED"
		default:
			errorMsg = fmt.Sprintf("Google Drive returned HTTP %d.", resp.StatusCode)
			errorCode = "DRIVE_ERROR"
		}

		log.Printf("[%s] DRIVE ERROR %d: %s | %s", reqId, resp.StatusCode, errorCode, driveDetail)
		status := resp.StatusCode
		if status >= 500 {
			status = http.StatusBadGateway
		}
		writeError(w, status, errorMsg, errorCode, driveDetail)
		return
	}

	// ── Stream the response ──────────────────────────────────────────────────
	outStatus := http.StatusOK
	if resp.StatusCode == 206 {
		outStatus = 206
	}

	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		w.Header().Set("Content-Range", cr)
	}

	w.WriteHeader(outStatus)

	// Stream with io.Copy — zero-copy, no buffering in memory
	// If client disconnects, r.Context() cancels and io.Copy stops
	written, err := io.Copy(w, resp.Body)
	if err != nil {
		if r.Context().Err() != nil {
			log.Printf("[%s] CLIENT CLOSE after %d bytes (seek/navigate)", reqId, written)
		} else {
			log.Printf("[%s] STREAM ERROR after %d bytes: %v", reqId, written, err)
		}
		return
	}
	log.Printf("[%s] COMPLETE %d bytes streamed", reqId, written)
}

// ── HMAC Token Verification ──────────────────────────────────────────────────

func verifyToken(fileId, token, expires string) bool {
	if token == "" || expires == "" {
		return false
	}

	expiresAt, err := strconv.ParseInt(expires, 10, 64)
	if err != nil || time.Now().Unix() > expiresAt {
		return false
	}

	mac := hmac.New(sha256.New, []byte(authToken))
	mac.Write([]byte(fmt.Sprintf("%s:%s", fileId, expires)))
	expected := hex.EncodeToString(mac.Sum(nil))

	tokenBytes, err := hex.DecodeString(token)
	if err != nil {
		return false
	}
	expectedBytes, _ := hex.DecodeString(expected)

	return hmac.Equal(tokenBytes, expectedBytes)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func writeError(w http.ResponseWriter, status int, msg, code, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorResponse{
		Error:       msg,
		Code:        code,
		DriveDetail: detail,
	})
}

func parseDriveError(body []byte) string {
	var data struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(body, &data) == nil {
		if data.Error.Message != "" {
			return data.Error.Message
		}
		if data.ErrorDescription != "" {
			return data.ErrorDescription
		}
	}
	s := string(body)
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "Not found.", "NOT_FOUND", "")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
