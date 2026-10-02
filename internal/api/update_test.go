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
			{"lower": "3.0.0", "lower_include": true, "upper": "3.1.0", "upper_include": true},
			{"upper": "1.0.0", "upper_include": false},
		},
		"severity":      "critical",
		"fixed_version": "3.1.1",
		"status":        "fixed",
	}
}

func TestUpdateVulnerabilitySuccess(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1001"))

	recorder := doJSON(t, router, http.MethodPut,
		"/vulnerabilities/CVE-2024-1001", validUpdateBody())
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var record map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, recorder.Body.String())
	}
	if record["id"] != "CVE-2024-1001" || record["component"] != "openssl" ||
		record["severity"] != "critical" || record["fixed_version"] != "3.1.1" ||
		record["status"] != "fixed" {
		t.Fatalf("scalar fields wrong: %v", record)
	}
	ranges, ok := record["affected_ranges"].([]any)
	if !ok || len(ranges) != 2 {
		t.Fatalf("affected_ranges wrong: %v", record["affected_ranges"])
	}
	first := ranges[0].(map[string]any)
	if first["lower"] != "3.0.0" || first["lower_include"] != true ||
		first["upper"] != "3.1.0" || first["upper_include"] != true {
		t.Fatalf("first range wrong: %v", first)
	}
	second := ranges[1].(map[string]any)
	if second["lower"] != nil || second["lower_include"] != nil ||
		second["upper"] != "1.0.0" || second["upper_include"] != false {
		t.Fatalf("second range wrong: %v", second)
	}

	loaded := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-2024-1001", nil)
	if loaded.Code != http.StatusOK {
		t.Fatalf("get after update status = %d", loaded.Code)
	}
	var stored map[string]any
	if err := json.Unmarshal(loaded.Body.Bytes(), &stored); err != nil {
		t.Fatalf("unmarshal stored: %v", err)
	}
	if stored["component"] != "openssl" || stored["severity"] != "critical" ||
		stored["fixed_version"] != "3.1.1" || stored["status"] != "fixed" {
		t.Fatalf("stored scalar fields not replaced: %v", stored)
	}
}

func TestUpdateVulnerabilityQueriesUseNewValues(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1002"))

	recorder := doJSON(t, router, http.MethodPut,
		"/vulnerabilities/CVE-2024-1002", validUpdateBody())
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
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
		"/vulnerabilities/affected?component=openssl&version=3.0.5", nil)
	var newHits []map[string]any
	if err := json.Unmarshal(newComponent.Body.Bytes(), &newHits); err != nil {
		t.Fatalf("unmarshal new hits: %v", err)
	}
	if len(newHits) != 1 || newHits[0]["id"] != "CVE-2024-1002" {
		t.Fatalf("new component range should match: %v", newHits)
	}

	outside := doJSON(t, router, http.MethodGet,
		"/vulnerabilities/affected?component=openssl&version=3.2.0", nil)
	var outsideHits []map[string]any
	if err := json.Unmarshal(outside.Body.Bytes(), &outsideHits); err != nil {
		t.Fatalf("unmarshal outside hits: %v", err)
	}
	if len(outsideHits) != 0 {
		t.Fatalf("new ranges should not match 3.2.0: %v", outsideHits)
	}

	listed := doJSON(t, router, http.MethodGet,
		"/vulnerabilities?component=openssl&severity=critical&status=fixed", nil)
	var page listResponseShape
	if err := json.Unmarshal(listed.Body.Bytes(), &page); err != nil {
		t.Fatalf("unmarshal list: %v body=%s", err, listed.Body.String())
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0]["id"] != "CVE-2024-1002" {
		t.Fatalf("list filters should find updated record: %s", listed.Body.String())
	}
}

type listResponseShape struct {
	Items []map[string]any `json:"items"`
	Total int              `json:"total"`
}

func TestUpdateVulnerabilityUnknownID(t *testing.T) {
	router := newTestRouter(t)

	recorder := doJSON(t, router, http.MethodPut,
		"/vulnerabilities/CVE-9999-9999", validUpdateBody())
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 body=%s", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); body != "error=VULNERABILITY_NOT_FOUND" {
		t.Fatalf("body = %q", body)
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "text/plain; charset=utf-8" {
		t.Fatalf("content-type = %q", contentType)
	}
}

func TestUpdateVulnerabilityInvalidInputBeforeIDLookup(t *testing.T) {
	cases := map[string]func(map[string]any){
		"missing component": func(b map[string]any) { delete(b, "component") },
		"empty component":   func(b map[string]any) { b["component"] = "" },
		"missing ranges":    func(b map[string]any) { delete(b, "affected_ranges") },
		"empty ranges":      func(b map[string]any) { b["affected_ranges"] = []any{} },
		"inverted range": func(b map[string]any) {
			b["affected_ranges"] = []any{map[string]any{"lower": "4.0", "lower_include": true, "upper": "1.0", "upper_include": true}}
		},
		"equal endpoints not both included": func(b map[string]any) {
			b["affected_ranges"] = []any{map[string]any{"lower": "2.0", "lower_include": true, "upper": "2.0", "upper_include": false}}
		},
		"bad bound version": func(b map[string]any) {
			b["affected_ranges"] = []any{map[string]any{"lower": "2.x", "lower_include": true}}
		},
		"missing include flag": func(b map[string]any) {
			b["affected_ranges"] = []any{map[string]any{"lower": "2.0", "upper": "3.0", "upper_include": true}}
		},
		"include flag not boolean": func(b map[string]any) {
			b["affected_ranges"] = []map[string]any{
				{"lower": "2.0", "lower_include": "yes", "upper": "3.0", "upper_include": true},
			}
		},
		"bad fixed version":     func(b map[string]any) { b["fixed_version"] = "nope" },
		"missing fixed version": func(b map[string]any) { delete(b, "fixed_version") },
		"bad severity":          func(b map[string]any) { b["severity"] = "urgent" },
		"bad status":            func(b map[string]any) { b["status"] = "closed" },
		"missing status":        func(b map[string]any) { delete(b, "status") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			router := newTestRouter(t)
			body := validUpdateBody()
			mutate(body)
			recorder := doJSON(t, router, http.MethodPut,
				"/vulnerabilities/CVE-9999-9999", body)
			if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
				t.Fatalf("unknown id invalid body: status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestUpdateVulnerabilityMalformedBodies(t *testing.T) {
	router := newTestRouter(t)
	for _, raw := range []string{
		"{not json",
		`["not","object"]`,
		`"a string"`,
		`{"component":"openssl"} trailing junk`,
	} {
		request := httptest.NewRequest(http.MethodPut, "/vulnerabilities/CVE-2024-1003", bytes.NewBufferString(raw))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
			t.Fatalf("%s: status=%d body=%q", raw, recorder.Code, recorder.Body.String())
		}
	}
}

func TestUpdateVulnerabilityIgnoresBodyIDAndUnknownFields(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1004"))

	body := validUpdateBody()
	body["id"] = "CVE-9999-CHANGED"
	body["extra"] = "ignored"
	recorder := doJSON(t, router, http.MethodPut,
		"/vulnerabilities/CVE-2024-1004", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var record map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record["id"] != "CVE-2024-1004" {
		t.Fatalf("id must stay path id: %v", record["id"])
	}
	if _, present := record["extra"]; present {
		t.Fatalf("unknown fields must not be stored: %v", record)
	}

	unchanged := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-9999-CHANGED", nil)
	if unchanged.Code != http.StatusNotFound {
		t.Fatalf("body id must not create or rename a record: %d", unchanged.Code)
	}
}

func TestUpdateVulnerabilityPreservesRangeOrder(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1005"))

	body := validUpdateBody()
	body["affected_ranges"] = []map[string]any{
		{"upper": "1.0.0", "upper_include": true},
		{"lower": "3.0.0", "lower_include": false, "upper": "4.0.0", "upper_include": false},
	}
	recorder := doJSON(t, router, http.MethodPut,
		"/vulnerabilities/CVE-2024-1005", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var record struct {
		Ranges []struct {
			Lower *string `json:"lower"`
			Upper *string `json:"upper"`
		} `json:"affected_ranges"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(record.Ranges) != 2 || record.Ranges[0].Upper == nil || *record.Ranges[0].Upper != "1.0.0" ||
		record.Ranges[1].Lower == nil || *record.Ranges[1].Lower != "3.0.0" {
		t.Fatalf("range order not preserved: %#v", record.Ranges)
	}
}

func TestUpdateVulnerabilityKeepsExactPathMatching(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1006"))

	for _, target := range []string{
		"/vulnerabilities/cve-2024-1006",
		"/vulnerabilities/CVE-2024-1006%20",
		"/vulnerabilities/CVE-2024-100",
	} {
		recorder := doJSON(t, router, http.MethodPut, target, validUpdateBody())
		if recorder.Code != http.StatusNotFound || recorder.Body.String() != "error=VULNERABILITY_NOT_FOUND" {
			t.Fatalf("%s: status=%d body=%q", target, recorder.Code, recorder.Body.String())
		}
	}

	loaded := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-2024-1006", nil)
	var stored map[string]any
	if err := json.Unmarshal(loaded.Body.Bytes(), &stored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if stored["component"] != "libxml2" || stored["severity"] != "high" || stored["status"] != "open" {
		t.Fatalf("failed lookups must not modify the record: %v", stored)
	}
}

func TestUpdateVulnerabilityDoesNotChangeStatusPatch(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1007"))

	replaced := doJSON(t, router, http.MethodPut,
		"/vulnerabilities/CVE-2024-1007", validUpdateBody())
	if replaced.Code != http.StatusOK {
		t.Fatalf("put status = %d body = %s", replaced.Code, replaced.Body.String())
	}

	patched := doJSON(t, router, http.MethodPatch,
		"/vulnerabilities/status/CVE-2024-1007", map[string]any{"status": "accepted"})
	if patched.Code != http.StatusOK {
		t.Fatalf("patch status = %d body = %s", patched.Code, patched.Body.String())
	}
	var record map[string]any
	if err := json.Unmarshal(patched.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record["status"] != "accepted" {
		t.Fatalf("status not patched: %v", record["status"])
	}
	if record["component"] != "openssl" || record["severity"] != "critical" ||
		record["fixed_version"] != "3.1.1" {
		t.Fatalf("patch must leave other fields from the PUT intact: %v", record)
	}
}

func TestUpdateVulnerabilityStorageFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1008"))
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recorder := doJSON(t, router, http.MethodPut,
		"/vulnerabilities/CVE-2024-1008", validUpdateBody())
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
