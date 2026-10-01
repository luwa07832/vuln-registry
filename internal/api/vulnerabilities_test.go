package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/store"
)

func newTestRouter(t *testing.T) http.Handler {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return NewRouter(st)
}

func doJSON(t *testing.T, router http.Handler, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	request := httptest.NewRequest(method, target, reader)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func validCreateBody(id string) map[string]any {
	return map[string]any{
		"id":        id,
		"component": "libxml2",
		"affected_ranges": []map[string]any{
			{"lower": "2.0", "lower_include": true, "upper": "2.9", "upper_include": false},
			{"upper": "1.5.0", "upper_include": true},
		},
		"severity":      "high",
		"fixed_version": "2.10.0",
		"status":        "open",
	}
}

func TestCreateVulnerabilitySuccess(t *testing.T) {
	router := newTestRouter(t)
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities", validCreateBody("CVE-2024-0001"))

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var record struct {
		ID        string `json:"id"`
		Component string `json:"component"`
		Ranges    []struct {
			Lower        *string `json:"lower"`
			LowerInclude *bool   `json:"lower_include"`
			Upper        *string `json:"upper"`
			UpperInclude *bool   `json:"upper_include"`
		} `json:"affected_ranges"`
		Severity     string `json:"severity"`
		FixedVersion string `json:"fixed_version"`
		Status       string `json:"status"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, recorder.Body.String())
	}
	if record.ID != "CVE-2024-0001" || record.Component != "libxml2" ||
		record.Severity != "high" || record.FixedVersion != "2.10.0" || record.Status != "open" {
		t.Fatalf("scalar fields wrong: %#v", record)
	}
	if len(record.Ranges) != 2 || record.Ranges[0].Lower == nil || *record.Ranges[0].Lower != "2.0" {
		t.Fatalf("ranges wrong: %#v", record.Ranges)
	}
	if record.Ranges[1].Lower != nil {
		t.Fatalf("open lower bound must serialize as null")
	}
}

func TestCreateVulnerabilityDuplicate(t *testing.T) {
	router := newTestRouter(t)
	first := doJSON(t, router, http.MethodPost, "/vulnerabilities", validCreateBody("CVE-2024-0002"))
	if first.Code != http.StatusCreated {
		t.Fatalf("first create status = %d", first.Code)
	}
	second := doJSON(t, router, http.MethodPost, "/vulnerabilities", validCreateBody("CVE-2024-0002"))
	if second.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", second.Code)
	}
	if body := second.Body.String(); body != "error=DUPLICATE_VULNERABILITY" {
		t.Fatalf("body = %q", body)
	}
}

func TestCreateVulnerabilityInvalidInputs(t *testing.T) {
	cases := map[string]func(map[string]any){
		"missing id":      func(b map[string]any) { delete(b, "id") },
		"empty component": func(b map[string]any) { b["component"] = "" },
		"missing ranges":  func(b map[string]any) { delete(b, "affected_ranges") },
		"empty ranges":    func(b map[string]any) { b["affected_ranges"] = []any{} },
		"inverted range": func(b map[string]any) {
			b["affected_ranges"] = []any{map[string]any{"lower": "3.0", "lower_include": true, "upper": "1.0", "upper_include": true}}
		},
		"bad lower version": func(b map[string]any) {
			b["affected_ranges"] = []any{map[string]any{"lower": "2.x", "lower_include": true}}
		},
		"missing lower include": func(b map[string]any) { b["affected_ranges"] = []any{map[string]any{"lower": "2.0"}} },
		"bad fixed version":     func(b map[string]any) { b["fixed_version"] = "nope" },
		"missing fixed version": func(b map[string]any) { delete(b, "fixed_version") },
		"bad severity":          func(b map[string]any) { b["severity"] = "urgent" },
		"bad status":            func(b map[string]any) { b["status"] = "closed" },
		"missing severity":      func(b map[string]any) { delete(b, "severity") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			router := newTestRouter(t)
			body := validCreateBody("CVE-2024-0003")
			mutate(body)
			recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities", body)
			if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestCreateVulnerabilityRejectsMalformedBody(t *testing.T) {
	router := newTestRouter(t)
	request := httptest.NewRequest(http.MethodPost, "/vulnerabilities", bytes.NewBufferString("{not json"))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func registerVulnerability(t *testing.T, router http.Handler, body map[string]any) {
	t.Helper()
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities", body)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAffectedQueryFiltersSortsAndProjects(t *testing.T) {
	router := newTestRouter(t)

	bodyA := validCreateBody("CVE-2024-0002")
	bodyB := validCreateBody("CVE-2024-0001")
	bodyC := validCreateBody("CVE-2024-0003")
	bodyC["component"] = "LIBXML2"
	registerVulnerability(t, router, bodyA)
	registerVulnerability(t, router, bodyB)
	registerVulnerability(t, router, bodyC)

	recorder := doJSON(t, router, http.MethodGet,
		"/vulnerabilities/affected?component=libxml2&version=1.5.0", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var results []map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &results); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2 (case-sensitive component): %v", len(results), results)
	}
	if results[0]["id"] != "CVE-2024-0001" || results[1]["id"] != "CVE-2024-0002" {
		t.Fatalf("results not id-sorted: %v", results)
	}
	for _, result := range results {
		for _, key := range []string{"id", "component", "matched_ranges", "severity", "fixed_version", "status"} {
			if _, ok := result[key]; !ok {
				t.Fatalf("result missing key %q: %v", key, result)
			}
		}
		matched, ok := result["matched_ranges"].([]any)
		if !ok || len(matched) != 1 {
			t.Fatalf("only the open-upper range should match: %v", result["matched_ranges"])
		}
	}

	// Boundary semantics: 2.0 is included, 2.9 excluded, 2.10 fixed/out of range.
	for _, tc := range []struct {
		version string
		want    int
	}{
		{"2.0", 2},
		{"2.9", 0},
		{"2.4.1", 2},
		{"1.5.1", 0},
	} {
		recorder := doJSON(t, router, http.MethodGet,
			"/vulnerabilities/affected?component=libxml2&version="+tc.version, nil)
		var hits []map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &hits); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(hits) != tc.want {
			t.Fatalf("version %s hits = %d, want %d (%v)", tc.version, len(hits), tc.want, hits)
		}
	}
}

func TestAffectedQueryEmptyResultIsStableArray(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0004"))

	recorder := doJSON(t, router, http.MethodGet,
		"/vulnerabilities/affected?component=libxml2&version=9.9.9", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if body := recorder.Body.String(); body != "[]" {
		t.Fatalf("body = %q, want []", body)
	}
}

func TestAffectedQueryInvalidInputs(t *testing.T) {
	router := newTestRouter(t)
	for _, target := range []string{
		"/vulnerabilities/affected?version=1.0",
		"/vulnerabilities/affected?component=libxml2",
		"/vulnerabilities/affected?component=libxml2&version=",
		"/vulnerabilities/affected?component=libxml2&version=1.x",
		"/vulnerabilities/affected?component=libxml2&version=1.",
	} {
		recorder := doJSON(t, router, http.MethodGet, target, nil)
		if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
			t.Fatalf("%s: status=%d body=%q", target, recorder.Code, recorder.Body.String())
		}
	}
}

func TestUpdateStatusSuccessAndFullRecord(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0005"))

	recorder := doJSON(t, router, http.MethodPatch,
		"/vulnerabilities/status/CVE-2024-0005", map[string]any{"status": "fixed"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var record map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record["status"] != "fixed" || record["id"] != "CVE-2024-0005" {
		t.Fatalf("updated record wrong: %v", record)
	}
	ranges, ok := record["affected_ranges"].([]any)
	if !ok || len(ranges) != 2 {
		t.Fatalf("full record must keep ranges: %v", record)
	}
}

func TestUpdateStatusUnknownID(t *testing.T) {
	router := newTestRouter(t)
	recorder := doJSON(t, router, http.MethodPatch,
		"/vulnerabilities/status/CVE-9999-0000", map[string]any{"status": "fixed"})
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if body := recorder.Body.String(); body != "error=VULNERABILITY_NOT_FOUND" {
		t.Fatalf("body = %q", body)
	}
}

func TestUpdateStatusInvalidInputs(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0006"))

	bad := doJSON(t, router, http.MethodPatch,
		"/vulnerabilities/status/CVE-2024-0006", map[string]any{"status": "closed"})
	if bad.Code != http.StatusBadRequest || bad.Body.String() != "error=INVALID_INPUT" {
		t.Fatalf("bad status: status=%d body=%q", bad.Code, bad.Body.String())
	}
	missing := doJSON(t, router, http.MethodPatch,
		"/vulnerabilities/status/CVE-2024-0006", map[string]any{})
	if missing.Code != http.StatusBadRequest || missing.Body.String() != "error=INVALID_INPUT" {
		t.Fatalf("missing status: status=%d body=%q", missing.Code, missing.Body.String())
	}
}
