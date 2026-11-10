package api

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// writeErrorCode is writeError plus a machine-readable code clients react to
// (e.g. on "quota" the app words the failure as a quota, not a full disk).
func writeErrorCode(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]string{"error": msg, "code": errCode})
}
