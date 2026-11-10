package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"time"

	"1time/internal/otcrypto"
)

const (
	defaultDuration = 7 * 24 * time.Hour
	maxDuration     = 30 * 24 * time.Hour
	maxBodyBytes    = 1 << 20 // same as the nginx default client_max_body_size
)

var (
	reHashedKey = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// Old links carry a short hex counter, new ones a 32-char hex id.
	reMessageID = regexp.MustCompile(`^[0-9a-f]{1,64}$`)
	// Ids chosen by the client (format v3): 128 bits in hex.
	reClientID = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// API serves the JSON endpoints under /api/.
type API struct {
	store Store
	log   *slog.Logger
	// enableUnsecSave turns on /api/unsecSave. Off by default: with it the
	// server receives the plaintext, which the web flow never does.
	enableUnsecSave bool
}

// APIOption configures optional API behaviour.
type APIOption func(*API)

// WithUnsecSave enables the server-side encryption endpoint.
func WithUnsecSave(on bool) APIOption { return func(a *API) { a.enableUnsecSave = on } }

func NewAPI(s Store, opts ...APIOption) *API {
	a := &API{store: s, log: slog.Default()}
	for _, o := range opts {
		o(a)
	}
	return a
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/saveSecret", a.saveSecret)
	mux.HandleFunc("POST /api/get", a.get)
	if a.enableUnsecSave {
		mux.HandleFunc("POST /api/unsecSave", a.unsecSave)
	}
	mux.HandleFunc("GET /api/health", a.health)
	// Unknown paths get 404 and wrong methods 405 from ServeMux itself.
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON enforces a JSON content type (blocks cross-site form posts
// that would skip the CORS preflight) and a body size limit.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) (int, error) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return http.StatusUnsupportedMediaType, errors.New("content-type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return http.StatusRequestEntityTooLarge, errors.New("request body too large")
		}
		return http.StatusBadRequest, errors.New("invalid json")
	}
	return 0, nil
}

func ttlFromSeconds(sec int) time.Duration {
	d := time.Duration(sec) * time.Second
	if sec <= 0 || d > maxDuration {
		return defaultDuration
	}
	return d
}

type saveSecretRequest struct {
	SecretMessage string `json:"secretMessage"`
	HashedKey     string `json:"hashedKey"`
	Duration      int    `json:"duration"`
	// ID is set by v3 clients, which derive it from the link key so that the
	// link carries only the key. Empty: the server picks a random id (v2).
	ID string `json:"id,omitempty"`
}

type saveSecretResponse struct {
	Status string `json:"status"`
	NewID  string `json:"newId"`
}

// saveSecret stores a message that the browser has already encrypted.
func (a *API) saveSecret(w http.ResponseWriter, r *http.Request) {
	var req saveSecretRequest
	if code, err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, code, saveSecretResponse{Status: err.Error(), NewID: "0"})
		return
	}
	if req.SecretMessage == "" || !reHashedKey.MatchString(req.HashedKey) {
		writeJSON(w, http.StatusBadRequest, saveSecretResponse{Status: "error", NewID: "0"})
		return
	}
	msg := StoredMessage{Encrypted: true, Message: req.SecretMessage, HashedKey: req.HashedKey}
	ttl := ttlFromSeconds(req.Duration)
	var (
		id  = req.ID
		err error
	)
	if id != "" {
		if !reClientID.MatchString(id) {
			writeJSON(w, http.StatusBadRequest, saveSecretResponse{Status: "error", NewID: "0"})
			return
		}
		var ok bool
		ok, err = a.store.SaveWithID(r.Context(), id, msg, ttl)
		if err == nil && !ok {
			// Only possible with a reused link key: the client makes a new one.
			writeJSON(w, http.StatusConflict, saveSecretResponse{Status: "id taken", NewID: "0"})
			return
		}
	} else {
		id, err = a.store.Save(r.Context(), msg, ttl)
	}
	if err != nil {
		a.log.Error("save message", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, saveSecretResponse{Status: "error", NewID: "0"})
		return
	}
	writeJSON(w, http.StatusOK, saveSecretResponse{Status: "ok", NewID: id})
}

type getRequest struct {
	ID        string `json:"id"`
	HashedKey string `json:"hashedKey"`
}

type getResponse struct {
	Status         string `json:"status"`
	CryptedMessage string `json:"cryptedMessage"`
}

// get returns the encrypted message once and deletes it atomically.
func (a *API) get(w http.ResponseWriter, r *http.Request) {
	var req getRequest
	if code, err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, code, getResponse{Status: err.Error(), CryptedMessage: "0"})
		return
	}
	if !reMessageID.MatchString(req.ID) || !reHashedKey.MatchString(req.HashedKey) {
		writeJSON(w, http.StatusOK, getResponse{Status: "no message", CryptedMessage: "0"})
		return
	}
	res, msg, err := a.store.Take(r.Context(), req.ID, req.HashedKey)
	if err != nil {
		a.log.Error("take message", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, getResponse{Status: "error", CryptedMessage: "0"})
		return
	}
	switch res {
	case FetchOK:
		writeJSON(w, http.StatusOK, getResponse{Status: "ok", CryptedMessage: msg})
	case FetchWrongKey:
		// Kept distinct from "no message": the UI uses it to ask for the
		// additional secret key. Ids are 128-bit random, so this does not
		// help to enumerate messages.
		writeJSON(w, http.StatusOK, getResponse{Status: "wrong key", CryptedMessage: "0"})
	default:
		writeJSON(w, http.StatusOK, getResponse{Status: "no message", CryptedMessage: "0"})
	}
}

type unsecSaveRequest struct {
	SecretMessage string `json:"secretMessage"`
	Duration      int    `json:"duration"`
}

type unsecSaveResponse struct {
	Status  string `json:"status"`
	NewLink string `json:"newLink"`
}

// unsecSave encrypts a plain text message on the server (for scripts and
// curl). The server sees the plaintext here, unlike in the web flow, so the
// endpoint is disabled unless ENABLE_UNSEC_SAVE=1. Scripts should prefer
// "1time send", which encrypts on the client. The result uses the same v2
// format as the browser.
func (a *API) unsecSave(w http.ResponseWriter, r *http.Request) {
	var req unsecSaveRequest
	if code, err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, code, unsecSaveResponse{Status: err.Error()})
		return
	}
	if req.SecretMessage == "" {
		writeJSON(w, http.StatusBadRequest, unsecSaveResponse{Status: "error"})
		return
	}
	linkKey, err := otcrypto.NewLinkKey()
	if err != nil {
		a.log.Error("random key", "err", err)
		writeJSON(w, http.StatusInternalServerError, unsecSaveResponse{Status: "error"})
		return
	}
	keys, err := otcrypto.Derive(linkKey, "")
	if err != nil {
		a.log.Error("derive", "err", err)
		writeJSON(w, http.StatusInternalServerError, unsecSaveResponse{Status: "error"})
		return
	}
	payload, err := otcrypto.Encrypt(keys, []byte(req.SecretMessage))
	if err != nil {
		a.log.Error("encrypt", "err", err)
		writeJSON(w, http.StatusInternalServerError, unsecSaveResponse{Status: "error"})
		return
	}
	ok, err := a.store.SaveWithID(r.Context(), keys.ID, StoredMessage{
		Encrypted: true,
		Message:   payload,
		HashedKey: keys.Token,
	}, ttlFromSeconds(req.Duration))
	if err == nil && !ok {
		err = errors.New("id collision")
	}
	if err != nil {
		a.log.Error("save message", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, unsecSaveResponse{Status: "error"})
		return
	}
	writeJSON(w, http.StatusOK, unsecSaveResponse{Status: "ok", NewLink: "/v/#" + otcrypto.Fragment(linkKey, keys.ID)})
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	if err := a.store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "redis unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
