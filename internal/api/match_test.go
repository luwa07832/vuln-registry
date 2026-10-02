package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/store"
)

func doRaw(t *testing.T, router http.Handler, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, target, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestMatchVulnerabilitiesOrderProjectionAndDuplicates(t *testing.T) {
	router := newTestRouter(t)

	bodyA := validCreateBody("CVE-2024-0002")
	bodyB := validCreateBody("CVE-2024-0001")
	bodyC := validCreateBody("CVE-2024-0003")
	bodyC["component"] = "LIBXML2"
	registerVulnerability(t, router, bodyA)
	registerVulnerability(t, router, bodyB)
	registerVulnerability(t, router, bodyC)

	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/match", map[string]any{
		"components": []map[string]string{
			{"component": "libxml2", "version": "2.4.1"},
			{"component": "unknown-lib", "version": "1.0"},
			{"component": "libxml2", "version": "2.4.1"},
			{"component": "LIBXML2", "version": "1.5.0"},
		},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Results []struct {
			Component       string `json:"component"`
			Version         string `json:"version"`
			Vulnerabilities []struct {
				ID            string           `json:"id"`
				Component     string           `json:"component"`
				MatchedRanges []map[string]any `json:"matched_ranges"`
				Severity      string           `json:"severity"`
				FixedVersion  string           `json:"fixed_version"`
				Status        string           `json:"status"`
			} `json:"vulnerabilities"`
		} `json:"results"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, recorder.Body.String())
	}
	if len(response.Results) != 4 {
		t.Fatalf("results = %d, want 4", len(response.Results))
	}

	first := response.Results[0]
	if first.Component != "libxml2" || first.Version != "2.4.1" {
		t.Fatalf("first item not echoed: %+v", first)
	}
	if len(first.Vulnerabilities) != 2 {
		t.Fatalf("first item hits = %d, want 2", len(first.Vulnerabilities))
	}
	if first.Vulnerabilities[0].ID != "CVE-2024-0001" || first.Vulnerabilities[1].ID != "CVE-2024-0002" {
		t.Fatalf("vulnerabilities not id-sorted: %+v", first.Vulnerabilities)
	}
	for _, hit := range first.Vulnerabilities {
		if hit.Component != "libxml2" || hit.Severity != "high" ||
			hit.FixedVersion != "2.10.0" || hit.Status != "open" {
			t.Fatalf("projection fields wrong: %+v", hit)
		}
		if len(hit.MatchedRanges) != 1 {
			t.Fatalf("matched_ranges = %v, want only the inclusive 2.0 bound range", hit.MatchedRanges)
		}
		matched := hit.MatchedRanges[0]
		if matched["lower"] != "2.0" || matched["upper"] != "2.9" {
			t.Fatalf("matched range wrong: %v", matched)
		}
	}

	if len(response.Results[1].Vulnerabilities) != 0 {
		t.Fatalf("unknown component must have empty hits: %+v", response.Results[1])
	}
	if len(response.Results[2].Vulnerabilities) != 2 {
		t.Fatalf("duplicate input must be handled independently: %+v", response.Results[2])
	}
	caseSensitive := response.Results[3]
	if caseSensitive.Component != "LIBXML2" || len(caseSensitive.Vulnerabilities) != 1 ||
		caseSensitive.Vulnerabilities[0].ID != "CVE-2024-0003" {
		t.Fatalf("component match must be case-sensitive: %+v", caseSensitive)
	}
}

func TestMatchVulnerabilitiesAllMissesStill200(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))

	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/match", map[string]any{
		"components": []map[string]string{
			{"component": "libxml2", "version": "9.9.9"},
			{"component": "other", "version": "1"},
		},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	var response struct {
		Results []struct {
			Vulnerabilities []any `json:"vulnerabilities"`
		} `json:"results"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, recorder.Body.String())
	}
	if len(response.Results) != 2 {
		t.Fatalf("results = %d", len(response.Results))
	}
	for index, result := range response.Results {
		if result.Vulnerabilities == nil || len(result.Vulnerabilities) != 0 {
			t.Fatalf("result %d must have empty array, got %v", index, result.Vulnerabilities)
		}
	}
}

func TestMatchVulnerabilitiesIgnoresStatus(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))
	update := doJSON(t, router, http.MethodPatch,
		"/vulnerabilities/status/CVE-2024-0001", map[string]any{"status": "fixed"})
	if update.Code != http.StatusOK {
		t.Fatalf("update status = %d", update.Code)
	}

	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/match", map[string]any{
		"components": []map[string]string{{"component": "libxml2", "version": "2.4.1"}},
	})
	var response struct {
		Results []struct {
			Vulnerabilities []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"vulnerabilities"`
		} `json:"results"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(response.Results[0].Vulnerabilities) != 1 ||
		response.Results[0].Vulnerabilities[0].Status != "fixed" {
		t.Fatalf("fixed-status vulnerability must still match: %+v", response.Results)
	}
}

func TestMatchVulnerabilitiesInvalidInputs(t *testing.T) {
	cases := map[string]string{
		"array instead of object": `[{"component":"libxml2","version":"1.0"}]`,
		"malformed json":          `{not json`,
		"missing components":      `{}`,
		"components not array":    `{"components":{}}`,
		"empty components":        `{"components":[]}`,
		"element not object":      `{"components":[42]}`,
		"null element":            `{"components":[null]}`,
		"missing component":       `{"components":[{"version":"1.0"}]}`,
		"empty component":         `{"components":[{"component":"","version":"1.0"}]}`,
		"numeric component":       `{"components":[{"component":7,"version":"1.0"}]}`,
		"null component":          `{"components":[{"component":null,"version":"1.0"}]}`,
		"missing version":         `{"components":[{"component":"libxml2"}]}`,
		"empty version":           `{"components":[{"component":"libxml2","version":""}]}`,
		"illegal version":         `{"components":[{"component":"libxml2","version":"1.x"}]}`,
		"numeric version":         `{"components":[{"component":"libxml2","version":1}]}`,
		"second element bad":      `{"components":[{"component":"libxml2","version":"1.0"},{"component":"","version":"2.0"}]}`,
		"101 items":               `{"components":` + matchBodyForCount(101) + `}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			router := newTestRouter(t)
			recorder := doRaw(t, router, "/vulnerabilities/match", body)
			if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestMatchVulnerabilitiesAccepts100ItemsAndExtraFields(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))

	recorder := doRaw(t, router, "/vulnerabilities/match",
		`{"unrelated":true,"components":`+matchBodyForCount(100)+`}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(response.Results) != 100 {
		t.Fatalf("results = %d, want 100", len(response.Results))
	}
}

func TestMatchVulnerabilitiesStorageFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0013"))
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recorder := doRaw(t, router, "/vulnerabilities/match",
		`{"components":[{"component":"libxml2","version":"2.4.1"}]}`)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, recorder.Body.String())
	}
	errorBody, ok := response["error"].(map[string]any)
	if !ok || errorBody["code"] != "internal_error" {
		t.Fatalf("error body wrong: %v", response)
	}
	if strings.Contains(recorder.Body.String(), "SQL") ||
		strings.Contains(recorder.Body.String(), "goroutine") ||
		strings.Contains(recorder.Body.String(), filepath.Dir(t.TempDir())) {
		t.Fatalf("body leaks internals: %s", recorder.Body.String())
	}
}

func TestMatchVulnerabilitiesCoexistsWithSingleComponentQuery(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))

	single := doJSON(t, router, http.MethodGet,
		"/vulnerabilities/affected?component=libxml2&version=2.4.1", nil)
	if single.Code != http.StatusOK {
		t.Fatalf("single query status = %d", single.Code)
	}
	batch := doJSON(t, router, http.MethodPost, "/vulnerabilities/match", map[string]any{
		"components": []map[string]string{{"component": "libxml2", "version": "2.4.1"}},
	})
	if batch.Code != http.StatusOK {
		t.Fatalf("batch status = %d body = %s", batch.Code, batch.Body.String())
	}
}

func matchBodyForCount(count int) string {
	var builder strings.Builder
	builder.WriteByte('[')
	for index := 0; index < count; index++ {
		if index > 0 {
			builder.WriteByte(',')
		}
		fmt.Fprintf(&builder, `{"component":"libxml2","version":"1.%d"}`, index)
	}
	builder.WriteByte(']')
	return builder.String()
}
