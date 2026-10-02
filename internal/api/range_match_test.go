package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/store"
)

func registerRangeVulnerability(t *testing.T, router http.Handler, id, component string, ranges []map[string]any) {
	t.Helper()
	body := map[string]any{
		"id":              id,
		"component":       component,
		"affected_ranges": ranges,
		"severity":        "high",
		"fixed_version":   "9.0.0",
		"status":          "open",
	}
	registerVulnerability(t, router, body)
}

func TestRangeMatchHitsProjectionAndOrder(t *testing.T) {
	router := newTestRouter(t)
	registerRangeVulnerability(t, router, "CVE-2024-0002", "libxml2", []map[string]any{
		{"lower": "2.0", "lower_include": true, "upper": "2.9", "upper_include": false},
	})
	registerRangeVulnerability(t, router, "CVE-2024-0001", "libxml2", []map[string]any{
		{"lower": "2.0", "lower_include": true, "upper": "2.9", "upper_include": false},
		{"upper": "1.5.0", "upper_include": true},
	})
	registerRangeVulnerability(t, router, "CVE-2024-0003", "other", []map[string]any{
		{"lower": "1.0", "lower_include": true, "upper": "2.0", "upper_include": true},
	})

	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/range-match", map[string]any{
		"queries": []map[string]any{
			{"component": "libxml2", "lower": "2.8", "upper": "3.0", "lower_include": true, "upper_include": true},
			{"component": "missing", "lower": "1", "upper": "2", "lower_include": true, "upper_include": true},
			{"component": "LIBXML2", "lower": "2.8", "upper": "2.8", "lower_include": true, "upper_include": true},
		},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Results []struct {
			Component    string `json:"component"`
			Lower        string `json:"lower"`
			Upper        string `json:"upper"`
			LowerInclude bool   `json:"lower_include"`
			UpperInclude bool   `json:"upper_include"`
			Vulns        []struct {
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
	if len(response.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(response.Results))
	}

	first := response.Results[0]
	if first.Component != "libxml2" || first.Lower != "2.8" || first.Upper != "3.0" ||
		!first.LowerInclude || !first.UpperInclude {
		t.Fatalf("query not echoed: %+v", first)
	}
	if len(first.Vulns) != 2 {
		t.Fatalf("hits = %d, want 2", len(first.Vulns))
	}
	if first.Vulns[0].ID != "CVE-2024-0001" || first.Vulns[1].ID != "CVE-2024-0002" {
		t.Fatalf("not id-sorted: %+v", first.Vulns)
	}
	for _, hit := range first.Vulns {
		if hit.Component != "libxml2" || hit.Severity != "high" ||
			hit.FixedVersion != "9.0.0" || hit.Status != "open" {
			t.Fatalf("projection wrong: %+v", hit)
		}
		if len(hit.MatchedRanges) != 1 {
			t.Fatalf("matched_ranges = %v, want only intersecting range", hit.MatchedRanges)
		}
		matched := hit.MatchedRanges[0]
		if matched["lower"] != "2.0" || matched["upper"] != "2.9" {
			t.Fatalf("wrong range kept: %v", matched)
		}
	}

	if response.Results[1].Vulns == nil || len(response.Results[1].Vulns) != 0 {
		t.Fatalf("missing component must be []: %+v", response.Results[1].Vulns)
	}
	if len(response.Results[2].Vulns) != 0 {
		t.Fatalf("component match must stay case-sensitive: %+v", response.Results[2].Vulns)
	}
}

func TestRangeMatchEndpointSemantics(t *testing.T) {
	router := newTestRouter(t)
	registerRangeVulnerability(t, router, "CVE-2024-0001", "libxml2", []map[string]any{
		{"lower": "1.0", "lower_include": false, "upper": "2.0", "upper_include": true},
		{"lower": "4.0", "lower_include": true},
	})
	registerRangeVulnerability(t, router, "CVE-2024-0002", "libxml2", []map[string]any{
		{"upper": "1.0", "upper_include": false},
	})

	query := func(lower, upper string, lowerInclude, upperInclude bool) map[string]any {
		return map[string]any{
			"component": "libxml2", "lower": lower, "upper": upper,
			"lower_include": lowerInclude, "upper_include": upperInclude,
		}
	}
	hitsFor := func(body map[string]any) []string {
		recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/range-match", body)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
		}
		var response struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulnerabilities"`
			} `json:"results"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		ids := []string{}
		for _, hit := range response.Results[0].Vulns {
			ids = append(ids, hit.ID)
		}
		return ids
	}

	if got := hitsFor(map[string]any{"queries": []map[string]any{query("0.5", "0.9", true, true)}}); len(got) != 1 || got[0] != "CVE-2024-0002" {
		t.Fatalf("below excluded lower: %v", got)
	}
	if got := hitsFor(map[string]any{"queries": []map[string]any{query("2.0", "3.0", false, true)}}); len(got) != 0 {
		t.Fatalf("touch where query excludes shared endpoint must not intersect: %v", got)
	}
	if got := hitsFor(map[string]any{"queries": []map[string]any{query("2.0", "2.5", true, true)}}); len(got) != 1 || got[0] != "CVE-2024-0001" {
		t.Fatalf("shared included endpoint: %v", got)
	}
	if got := hitsFor(map[string]any{"queries": []map[string]any{query("2.5", "3.9", true, true)}}); len(got) != 0 {
		t.Fatalf("gap: %v", got)
	}
	if got := hitsFor(map[string]any{"queries": []map[string]any{query("3.0", "4.0", true, false)}}); len(got) != 0 {
		t.Fatalf("touch where query upper excludes shared endpoint must not intersect: %v", got)
	}
	if got := hitsFor(map[string]any{"queries": []map[string]any{query("5", "6", true, true)}}); len(got) != 1 || got[0] != "CVE-2024-0001" {
		t.Fatalf("open registered upper stays unbounded: %v", got)
	}
}

func TestRangeMatchIgnoresStatus(t *testing.T) {
	router := newTestRouter(t)
	registerRangeVulnerability(t, router, "CVE-2024-0001", "libxml2", []map[string]any{
		{"lower": "1.0", "lower_include": true, "upper": "2.0", "upper_include": true},
	})
	update := doJSON(t, router, http.MethodPatch,
		"/vulnerabilities/status/CVE-2024-0001", map[string]any{"status": "fixed"})
	if update.Code != http.StatusOK {
		t.Fatalf("update status = %d", update.Code)
	}

	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/range-match", map[string]any{
		"queries": []map[string]any{
			{"component": "libxml2", "lower": "1.5", "upper": "1.6", "lower_include": true, "upper_include": true},
		},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Results []struct {
			Vulns []struct {
				Status string `json:"status"`
			} `json:"vulnerabilities"`
		} `json:"results"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(response.Results[0].Vulns) != 1 || response.Results[0].Vulns[0].Status != "fixed" {
		t.Fatalf("fixed-status record must still match: %+v", response.Results)
	}
}

func TestRangeMatchInvalidInputs(t *testing.T) {
	cases := map[string]string{
		"array instead of object": `[{"component":"libxml2","lower":"1","upper":"2","lower_include":true,"upper_include":true}]`,
		"malformed json":          `{not json`,
		"missing queries":         `{}`,
		"queries not array":       `{"queries":{}}`,
		"queries null":            `{"queries":null}`,
		"empty queries":           `{"queries":[]}`,
		"element not object":      `{"queries":[42]}`,
		"null element":            `{"queries":[null]}`,
		"missing component":       `{"queries":[{"lower":"1","upper":"2","lower_include":true,"upper_include":true}]}`,
		"empty component":         `{"queries":[{"component":"","lower":"1","upper":"2","lower_include":true,"upper_include":true}]}`,
		"numeric component":       `{"queries":[{"component":7,"lower":"1","upper":"2","lower_include":true,"upper_include":true}]}`,
		"missing lower":           `{"queries":[{"component":"libxml2","upper":"2","lower_include":true,"upper_include":true}]}`,
		"missing upper":           `{"queries":[{"component":"libxml2","lower":"1","lower_include":true,"upper_include":true}]}`,
		"empty lower":             `{"queries":[{"component":"libxml2","lower":"","upper":"2","lower_include":true,"upper_include":true}]}`,
		"illegal lower":           `{"queries":[{"component":"libxml2","lower":"1.x","upper":"2","lower_include":true,"upper_include":true}]}`,
		"numeric lower":           `{"queries":[{"component":"libxml2","lower":1,"upper":"2","lower_include":true,"upper_include":true}]}`,
		"missing lower_include":   `{"queries":[{"component":"libxml2","lower":"1","upper":"2","upper_include":true}]}`,
		"missing upper_include":   `{"queries":[{"component":"libxml2","lower":"1","upper":"2","lower_include":true}]}`,
		"string include flag":     `{"queries":[{"component":"libxml2","lower":"1","upper":"2","lower_include":"true","upper_include":true}]}`,
		"null include flag":       `{"queries":[{"component":"libxml2","lower":"1","upper":"2","lower_include":null,"upper_include":true}]}`,
		"lower above upper":       `{"queries":[{"component":"libxml2","lower":"2","upper":"1","lower_include":true,"upper_include":true}]}`,
		"equal bounds lower open": `{"queries":[{"component":"libxml2","lower":"1","upper":"1","lower_include":false,"upper_include":true}]}`,
		"equal bounds upper open": `{"queries":[{"component":"libxml2","lower":"1","upper":"1","lower_include":true,"upper_include":false}]}`,
		"second element bad":      `{"queries":[{"component":"libxml2","lower":"1","upper":"2","lower_include":true,"upper_include":true},{"component":"","lower":"1","upper":"2","lower_include":true,"upper_include":true}]}`,
		"101 items":               `{"unrelated":true,"queries":` + rangeMatchBodyForCount(101) + `}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			router := newTestRouter(t)
			recorder := doRaw(t, router, "/vulnerabilities/range-match", body)
			if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestRangeMatchAccepts100ItemsEqualBoundsAndExtraFields(t *testing.T) {
	router := newTestRouter(t)
	registerRangeVulnerability(t, router, "CVE-2024-0001", "libxml2", []map[string]any{
		{"lower": "2.4", "lower_include": true, "upper": "2.4", "upper_include": true},
	})

	recorder := doRaw(t, router, "/vulnerabilities/range-match",
		`{"unrelated":true,"queries":`+rangeMatchBodyForCount(100)+`}`)
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

	single := doJSON(t, router, http.MethodPost, "/vulnerabilities/range-match", map[string]any{
		"queries": []map[string]any{
			{"component": "libxml2", "lower": "2.4.0", "upper": "2.4", "lower_include": true, "upper_include": true},
		},
	})
	if single.Code != http.StatusOK {
		t.Fatalf("equal-bounds query status = %d body = %s", single.Code, single.Body.String())
	}
	var singleResponse struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulnerabilities"`
		} `json:"results"`
	}
	if err := json.Unmarshal(single.Body.Bytes(), &singleResponse); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(singleResponse.Results[0].Vulns) != 1 {
		t.Fatalf("2.4.0 == 2.4 must intersect single-version range: %+v", singleResponse.Results)
	}
}

func TestRangeMatchStorageFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)
	registerRangeVulnerability(t, router, "CVE-2024-0013", "libxml2", []map[string]any{
		{"lower": "1.0", "lower_include": true, "upper": "2.0", "upper_include": true},
	})
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recorder := doRaw(t, router, "/vulnerabilities/range-match",
		`{"queries":[{"component":"libxml2","lower":"1.0","upper":"2.0","lower_include":true,"upper_include":true}]}`)
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
		strings.Contains(recorder.Body.String(), "goroutine") {
		t.Fatalf("body leaks internals: %s", recorder.Body.String())
	}
}

func TestRangeMatchCoexistsWithVersionMatch(t *testing.T) {
	router := newTestRouter(t)
	registerRangeVulnerability(t, router, "CVE-2024-0001", "libxml2", []map[string]any{
		{"lower": "2.0", "lower_include": true, "upper": "2.9", "upper_include": false},
	})

	versionMatch := doJSON(t, router, http.MethodPost, "/vulnerabilities/match", map[string]any{
		"components": []map[string]string{{"component": "libxml2", "version": "2.4.1"}},
	})
	if versionMatch.Code != http.StatusOK {
		t.Fatalf("version match status = %d", versionMatch.Code)
	}
	rangeMatch := doJSON(t, router, http.MethodPost, "/vulnerabilities/range-match", map[string]any{
		"queries": []map[string]any{
			{"component": "libxml2", "lower": "2.4", "upper": "2.5", "lower_include": true, "upper_include": true},
		},
	})
	if rangeMatch.Code != http.StatusOK {
		t.Fatalf("range match status = %d body = %s", rangeMatch.Code, rangeMatch.Body.String())
	}
}

func rangeMatchBodyForCount(count int) string {
	var builder strings.Builder
	builder.WriteByte('[')
	for index := 0; index < count; index++ {
		if index > 0 {
			builder.WriteByte(',')
		}
		fmt.Fprintf(&builder, `{"component":"libxml2","lower":"1.%d","upper":"1.%d","lower_include":true,"upper_include":true}`, index, index)
	}
	builder.WriteByte(']')
	return builder.String()
}
