package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/store"
)

func validUpdateBody() map[string]any {
	return map[string]any{
		"component": "openssl",
		"affected_ranges": []map[string]any{
			{"lower": "3.0.0", "lower_include": true, "upper": "3.2.1", "upper_include": true},
		},
		"severity":      "critical",
		"fixed_version": "3.2.2",
		"status":        "in_progress",
	}
}

func doRawPut(t *testing.T, router http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestReplaceVulnerabilitySuccessAndFullRecord(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1000"))

	body := validUpdateBody()
	body["id"] = "CVE-2024-9999"
	body["unexpected"] = "ignored"
	recorder := doJSON(t, router, http.MethodPut, "/vulnerabilities/CVE-2024-1000", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var record map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, recorder.Body.String())
	}
	if record["id"] != "CVE-2024-1000" || record["component"] != "openssl" ||
		record["severity"] != "critical" || record["fixed_version"] != "3.2.2" ||
		record["status"] != "in_progress" {
		t.Fatalf("replaced scalar fields wrong: %v", record)
	}
	ranges, ok := record["affected_ranges"].([]any)
	if !ok || len(ranges) != 1 {
		t.Fatalf("affected_ranges wrong: %v", record["affected_ranges"])
	}
	first := ranges[0].(map[string]any)
	if first["lower"] != "3.0.0" || first["lower_include"] != true ||
		first["upper"] != "3.2.1" || first["upper_include"] != true {
		t.Fatalf("replaced range wrong: %v", first)
	}

	stored := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-2024-1000", nil)
	if stored.Code != http.StatusOK {
		t.Fatalf("get after replace: %d %s", stored.Code, stored.Body.String())
	}
	if err := json.Unmarshal(stored.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal stored: %v", err)
	}
	if record["component"] != "openssl" || record["severity"] != "critical" ||
		record["fixed_version"] != "3.2.2" || record["status"] != "in_progress" {
		t.Fatalf("stored record not replaced: %v", record)
	}
	if ranges := record["affected_ranges"].([]any); len(ranges) != 1 {
		t.Fatalf("stored ranges not replaced: %v", record["affected_ranges"])
	}

	oldComponent := doJSON(t, router, http.MethodGet,
		"/vulnerabilities/affected?component=libxml2&version=2.4.1", nil)
	var oldHits []map[string]any
	if err := json.Unmarshal(oldComponent.Body.Bytes(), &oldHits); err != nil {
		t.Fatalf("unmarshal old hits: %v", err)
	}
	if len(oldHits) != 0 {
		t.Fatalf("old component must no longer match: %v", oldHits)
	}
	newComponent := doJSON(t, router, http.MethodGet,
		"/vulnerabilities/affected?component=openssl&version=3.1.0", nil)
	var newHits []map[string]any
	if err := json.Unmarshal(newComponent.Body.Bytes(), &newHits); err != nil {
		t.Fatalf("unmarshal new hits: %v", err)
	}
	if len(newHits) != 1 || newHits[0]["id"] != "CVE-2024-1000" {
		t.Fatalf("new component must match: %v", newHits)
	}

	notFound := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-2024-9999", nil)
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("body id must not create or rename: status=%d", notFound.Code)
	}
}

func TestReplaceVulnerabilityPreservesOrderAndOpenBounds(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1001"))

	body := map[string]any{
		"component": "zlib",
		"affected_ranges": []map[string]any{
			{"upper": "1.0.0", "upper_include": false},
			{"lower": "2.0.0", "lower_include": true},
		},
		"severity":      "low",
		"fixed_version": "3.0.0",
		"status":        "fixed",
	}
	recorder := doJSON(t, router, http.MethodPut, "/vulnerabilities/CVE-2024-1001", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var record struct {
		Ranges []struct {
			Lower        *string `json:"lower"`
			LowerInclude *bool   `json:"lower_include"`
			Upper        *string `json:"upper"`
			UpperInclude *bool   `json:"upper_include"`
		} `json:"affected_ranges"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(record.Ranges) != 2 {
		t.Fatalf("ranges = %d, want 2", len(record.Ranges))
	}
	if record.Ranges[0].Lower != nil || record.Ranges[0].LowerInclude != nil ||
		record.Ranges[0].Upper == nil || *record.Ranges[0].Upper != "1.0.0" {
		t.Fatalf("first range wrong: %#v", record.Ranges[0])
	}
	if record.Ranges[1].Upper != nil || record.Ranges[1].UpperInclude != nil ||
		record.Ranges[1].Lower == nil || *record.Ranges[1].Lower != "2.0.0" {
		t.Fatalf("second range wrong: %#v", record.Ranges[1])
	}
}

func TestReplaceVulnerabilityUnknownID(t *testing.T) {
	router := newTestRouter(t)
	recorder := doJSON(t, router, http.MethodPut,
		"/vulnerabilities/CVE-9999-1000", validUpdateBody())
	if recorder.Code != http.StatusNotFound || recorder.Body.String() != "error=VULNERABILITY_NOT_FOUND" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestReplaceVulnerabilityMatchesIDExactly(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1002"))

	for _, target := range []string{
		"/vulnerabilities/cve-2024-1002",
		"/vulnerabilities/CVE-2024-1002%20",
	} {
		recorder := doJSON(t, router, http.MethodPut, target, validUpdateBody())
		if recorder.Code != http.StatusNotFound || recorder.Body.String() != "error=VULNERABILITY_NOT_FOUND" {
			t.Fatalf("%s: status=%d body=%q", target, recorder.Code, recorder.Body.String())
		}
	}
}

func TestReplaceVulnerabilityInvalidInputs(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1003"))

	cases := map[string]map[string]any{
		"missing component":     without(validUpdateBody(), "component"),
		"empty component":       withValue(validUpdateBody(), "component", ""),
		"missing ranges":        without(validUpdateBody(), "affected_ranges"),
		"empty ranges":          withValue(validUpdateBody(), "affected_ranges", []map[string]any{}),
		"missing severity":      without(validUpdateBody(), "severity"),
		"bad severity":          withValue(validUpdateBody(), "severity", "urgent"),
		"missing status":        without(validUpdateBody(), "status"),
		"bad status":            withValue(validUpdateBody(), "status", "closed"),
		"missing fixed version": without(validUpdateBody(), "fixed_version"),
		"bad fixed version":     withValue(validUpdateBody(), "fixed_version", "v3"),
		"range missing include": withValue(validUpdateBody(), "affected_ranges", []map[string]any{
			{"lower": "3.0.0", "upper": "3.2.1", "upper_include": true},
		}),
		"range inverted": withValue(validUpdateBody(), "affected_ranges", []map[string]any{
			{"lower": "4.0.0", "lower_include": true, "upper": "3.2.1", "upper_include": true},
		}),
		"range equal exclusive": withValue(validUpdateBody(), "affected_ranges", []map[string]any{
			{"lower": "3.2.1", "lower_include": true, "upper": "3.2.1", "upper_include": false},
		}),
		"range bad bound": withValue(validUpdateBody(), "affected_ranges", []map[string]any{
			{"lower": "3.x", "lower_include": true},
		}),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := doJSON(t, router, http.MethodPut,
				"/vulnerabilities/CVE-2024-1003", body)
			if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}

	array := doRawPut(t, router, http.MethodPut,
		"/vulnerabilities/CVE-2024-1003", `[{"component":"openssl"}]`)
	if array.Code != http.StatusBadRequest || array.Body.String() != "error=INVALID_INPUT" {
		t.Fatalf("array body: status=%d body=%q", array.Code, array.Body.String())
	}
	malformed := doRawPut(t, router, http.MethodPut,
		"/vulnerabilities/CVE-2024-1003", `{not json`)
	if malformed.Code != http.StatusBadRequest || malformed.Body.String() != "error=INVALID_INPUT" {
		t.Fatalf("malformed body: status=%d body=%q", malformed.Code, malformed.Body.String())
	}

	recorder := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-2024-1003", nil)
	var record map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record["component"] != "libxml2" || record["severity"] != "high" || record["status"] != "open" {
		t.Fatalf("failed replace must leave record untouched: %v", record)
	}
}

func TestReplaceVulnerabilityValidatesBodyBeforeID(t *testing.T) {
	router := newTestRouter(t)

	recorder := doJSON(t, router, http.MethodPut,
		"/vulnerabilities/CVE-9999-9999", without(validUpdateBody(), "component"))
	if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
		t.Fatalf("unknown id with invalid body: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestReplaceVulnerabilityStorageFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1004"))
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recorder := doJSON(t, router, http.MethodPut,
		"/vulnerabilities/CVE-2024-1004", validUpdateBody())
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, recorder.Body.String())
	}
	errorBody, ok := response["error"].(map[string]any)
	if !ok || errorBody["code"] != "internal_error" || errorBody["message"] != "request could not be completed" {
		t.Fatalf("error body wrong: %v", response)
	}
}

func TestReplaceKeepsStatusPatchScoped(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1005"))

	replaced := doJSON(t, router, http.MethodPut,
		"/vulnerabilities/CVE-2024-1005", validUpdateBody())
	if replaced.Code != http.StatusOK {
		t.Fatalf("replace: %d %s", replaced.Code, replaced.Body.String())
	}
	patched := doJSON(t, router, http.MethodPatch,
		"/vulnerabilities/status/CVE-2024-1005", map[string]any{"status": "fixed"})
	if patched.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", patched.Code, patched.Body.String())
	}
	var record map[string]any
	if err := json.Unmarshal(patched.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record["status"] != "fixed" || record["component"] != "openssl" ||
		record["severity"] != "critical" || record["fixed_version"] != "3.2.2" {
		t.Fatalf("patch must change only status: %v", record)
	}
}

func without(body map[string]any, key string) map[string]any {
	copied := map[string]any{}
	for k, v := range body {
		if k != key {
			copied[k] = v
		}
	}
	return copied
}

func withValue(body map[string]any, key string, value any) map[string]any {
	copied := without(body, key)
	copied[key] = value
	return copied
}
