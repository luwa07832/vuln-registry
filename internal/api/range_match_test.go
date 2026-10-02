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

func TestRangeMatchOrderProjectionAndEcho(t *testing.T) {
	router := newTestRouter(t)

	bodyA := validCreateBody("CVE-2024-0002")
	bodyB := validCreateBody("CVE-2024-0001")
	bodyC := validCreateBody("CVE-2024-0003")
	bodyC["component"] = "LIBXML2"
	registerVulnerability(t, router, bodyA)
	registerVulnerability(t, router, bodyB)
	registerVulnerability(t, router, bodyC)

	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/range-match", map[string]any{
		"queries": []map[string]any{
			{"component": "libxml2", "lower": "2.0", "upper": "2.4", "lower_include": true, "upper_include": true},
			{"component": "unknown-lib", "lower": "1.0", "upper": "2.0", "lower_include": true, "upper_include": true},
			{"component": "libxml2", "lower": "2.9", "upper": "3.0", "lower_include": false, "upper_include": true},
			{"component": "LIBXML2", "lower": "1.0", "upper": "2.0", "lower_include": true, "upper_include": true},
		},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Results []struct {
			Component       string `json:"component"`
			Lower           string `json:"lower"`
			Upper           string `json:"upper"`
			LowerInclude    bool   `json:"lower_include"`
			UpperInclude    bool   `json:"upper_include"`
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
	if first.Component != "libxml2" || first.Lower != "2.0" || first.Upper != "2.4" ||
		!first.LowerInclude || !first.UpperInclude {
		t.Fatalf("first query not echoed: %+v", first)
	}
	if len(first.Vulnerabilities) != 2 {
		t.Fatalf("first hits = %d, want 2", len(first.Vulnerabilities))
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
			t.Fatalf("matched_ranges = %v, want only the intersecting range", hit.MatchedRanges)
		}
		matched := hit.MatchedRanges[0]
		if matched["lower"] != "2.0" || matched["upper"] != "2.9" {
			t.Fatalf("matched range wrong: %v", matched)
		}
	}

	if len(response.Results[1].Vulnerabilities) != 0 {
		t.Fatalf("unknown component must have empty hits: %+v", response.Results[1])
	}
	if len(response.Results[2].Vulnerabilities) != 0 {
		t.Fatalf("excluded endpoint must not intersect: %+v", response.Results[2])
	}
	caseSensitive := response.Results[3]
	if caseSensitive.Component != "LIBXML2" || len(caseSensitive.Vulnerabilities) != 1 ||
		caseSensitive.Vulnerabilities[0].ID != "CVE-2024-0003" {
		t.Fatalf("component match must be case-sensitive: %+v", caseSensitive)
	}
}

func TestRangeMatchInvalidInputs(t *testing.T) {
	validItem := `{"component":"libxml2","lower":"1.0","upper":"2.0","lower_include":true,"upper_include":false}`
	cases := map[string]string{
		"array instead of object":  `[` + validItem + `]`,
		"malformed json":           `{not json`,
		"missing queries":          `{}`,
		"queries not array":        `{"queries":{}}`,
		"empty queries":            `{"queries":[]}`,
		"element not object":       `{"queries":[42]}`,
		"null element":             `{"queries":[null]}`,
		"missing component":        `{"queries":[{"lower":"1.0","upper":"2.0","lower_include":true,"upper_include":true}]}`,
		"empty component":          `{"queries":[{"component":"","lower":"1.0","upper":"2.0","lower_include":true,"upper_include":true}]}`,
		"numeric component":        `{"queries":[{"component":7,"lower":"1.0","upper":"2.0","lower_include":true,"upper_include":true}]}`,
		"null component":           `{"queries":[{"component":null,"lower":"1.0","upper":"2.0","lower_include":true,"upper_include":true}]}`,
		"missing lower":            `{"queries":[{"component":"libxml2","upper":"2.0","lower_include":true,"upper_include":true}]}`,
		"empty lower":              `{"queries":[{"component":"libxml2","lower":"","upper":"2.0","lower_include":true,"upper_include":true}]}`,
		"null lower":               `{"queries":[{"component":"libxml2","lower":null,"upper":"2.0","lower_include":true,"upper_include":true}]}`,
		"numeric lower":            `{"queries":[{"component":"libxml2","lower":1,"upper":"2.0","lower_include":true,"upper_include":true}]}`,
		"missing upper":            `{"queries":[{"component":"libxml2","lower":"1.0","lower_include":true,"upper_include":true}]}`,
		"empty upper":              `{"queries":[{"component":"libxml2","lower":"1.0","upper":"","lower_include":true,"upper_include":true}]}`,
		"illegal lower":            `{"queries":[{"component":"libxml2","lower":"1.x","upper":"2.0","lower_include":true,"upper_include":true}]}`,
		"illegal upper":            `{"queries":[{"component":"libxml2","lower":"1.0","upper":"2..0","lower_include":true,"upper_include":true}]}`,
		"missing lower_include":    `{"queries":[{"component":"libxml2","lower":"1.0","upper":"2.0","upper_include":true}]}`,
		"null lower_include":       `{"queries":[{"component":"libxml2","lower":"1.0","upper":"2.0","lower_include":null,"upper_include":true}]}`,
		"string lower_include":     `{"queries":[{"component":"libxml2","lower":"1.0","upper":"2.0","lower_include":"true","upper_include":true}]}`,
		"missing upper_include":    `{"queries":[{"component":"libxml2","lower":"1.0","upper":"2.0","lower_include":true}]}`,
		"null upper_include":       `{"queries":[{"component":"libxml2","lower":"1.0","upper":"2.0","lower_include":true,"upper_include":null}]}`,
		"numeric upper_include":    `{"queries":[{"component":"libxml2","lower":"1.0","upper":"2.0","lower_include":true,"upper_include":1}]}`,
		"lower greater than upper": `{"queries":[{"component":"libxml2","lower":"2.1","upper":"2.0","lower_include":true,"upper_include":true}]}`,
		"equal bounds lower open":  `{"queries":[{"component":"libxml2","lower":"2.0","upper":"2.0","lower_include":false,"upper_include":true}]}`,
		"equal bounds upper open":  `{"queries":[{"component":"libxml2","lower":"2.0","upper":"2.0","lower_include":true,"upper_include":false}]}`,
		"second element bad":       `{"queries":[` + validItem + `,{"component":"","lower":"1.0","upper":"2.0","lower_include":true,"upper_include":true}]}`,
		"101 items":                `{"queries":` + rangeMatchBodyForCount(101) + `}`,
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

func TestRangeMatchAcceptsEqualInclusiveBounds100ItemsAndExtraFields(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))

	recorder := doRaw(t, router, "/vulnerabilities/range-match",
		`{"unrelated":true,"queries":`+rangeMatchBodyForCount(100)+`}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("100 items status = %d body = %s", recorder.Code, recorder.Body.String())
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
			{"component": "libxml2", "lower": "2.0", "upper": "2.0", "lower_include": true, "upper_include": true},
		},
	})
	if single.Code != http.StatusOK {
		t.Fatalf("equal inclusive bounds status = %d body = %s", single.Code, single.Body.String())
	}
}

func TestRangeMatchStorageFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0013"))
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recorder := doRaw(t, router, "/vulnerabilities/range-match",
		`{"queries":[{"component":"libxml2","lower":"2.0","upper":"2.5","lower_include":true,"upper_include":true}]}`)
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
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))

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
		fmt.Fprintf(&builder, `{"component":"libxml2","lower":"1.%d","upper":"1.%d","lower_include":true,"upper_include":false}`, index, index+1)
	}
	builder.WriteByte(']')
	return builder.String()
}

func TestRangeMatchOpenBoundsAndMultipleRanges(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))

	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/range-match", map[string]any{
		"queries": []map[string]any{
			{"component": "libxml2", "lower": "0.1", "upper": "1.5.0", "lower_include": true, "upper_include": true},
			{"component": "libxml2", "lower": "2.9", "upper": "4.0", "lower_include": false, "upper_include": false},
			{"component": "libxml2", "lower": "1.5.1", "upper": "1.9", "lower_include": true, "upper_include": true},
		},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Results []struct {
			Vulnerabilities []struct {
				ID            string           `json:"id"`
				MatchedRanges []map[string]any `json:"matched_ranges"`
			} `json:"vulnerabilities"`
		} `json:"results"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	hits := response.Results[0].Vulnerabilities
	if len(hits) != 1 || len(hits[0].MatchedRanges) != 1 {
		t.Fatalf("open-lower range must intersect at included 1.5.0: %+v", response.Results[0])
	}
	if hits[0].MatchedRanges[0]["upper"] != "1.5.0" {
		t.Fatalf("wrong range kept: %v", hits[0].MatchedRanges)
	}
	if len(response.Results[1].Vulnerabilities) != 0 {
		t.Fatalf("query starting beyond excluded upper must miss: %+v", response.Results[1])
	}
	if len(response.Results[2].Vulnerabilities) != 0 {
		t.Fatalf("gap between ranges must miss: %+v", response.Results[2])
	}
}

func TestRangeMatchAllMissesStill200(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))

	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/range-match", map[string]any{
		"queries": []map[string]any{
			{"component": "libxml2", "lower": "9.0", "upper": "9.9", "lower_include": true, "upper_include": true},
			{"component": "other", "lower": "1", "upper": "2", "lower_include": true, "upper_include": true},
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
		t.Fatalf("unmarshal: %v", err)
	}
	if len(response.Results) != 2 {
		t.Fatalf("results = %d", len(response.Results))
	}
	for index, result := range response.Results {
		if result.Vulnerabilities == nil || len(result.Vulnerabilities) != 0 {
			t.Fatalf("result %d must carry stable empty array, got %v", index, result.Vulnerabilities)
		}
	}
}

func TestRangeMatchIgnoresStatus(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))
	update := doJSON(t, router, http.MethodPatch,
		"/vulnerabilities/status/CVE-2024-0001", map[string]any{"status": "fixed"})
	if update.Code != http.StatusOK {
		t.Fatalf("update status = %d", update.Code)
	}

	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/range-match", map[string]any{
		"queries": []map[string]any{
			{"component": "libxml2", "lower": "2.0", "upper": "2.5", "lower_include": true, "upper_include": true},
		},
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
