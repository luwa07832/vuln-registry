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

func doRaw(t *testing.T, router http.Handler, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, target, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func matchEntry(component, version string) map[string]any {
	return map[string]any{"component": component, "version": version}
}

func matchBody(entries ...map[string]any) map[string]any {
	items := make([]any, len(entries))
	for index, entry := range entries {
		items[index] = entry
	}
	return map[string]any{"components": items}
}

type matchTestVulnerability struct {
	ID            string           `json:"id"`
	Component     string           `json:"component"`
	MatchedRanges []map[string]any `json:"matched_ranges"`
	Severity      string           `json:"severity"`
	FixedVersion  string           `json:"fixed_version"`
	Status        string           `json:"status"`
}

type matchTestResult struct {
	Component       string                   `json:"component"`
	Version         string                   `json:"version"`
	Vulnerabilities []matchTestVulnerability `json:"vulnerabilities"`
}

type matchTestResponse struct {
	Results []matchTestResult `json:"results"`
}

func doMatch(t *testing.T, router http.Handler, body any) matchTestResponse {
	t.Helper()
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/match", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response matchTestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, recorder.Body.String())
	}
	return response
}

func seedMatchRouter(t *testing.T) http.Handler {
	t.Helper()
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0002"))
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))
	bodyFixed := validCreateBody("CVE-2024-0005")
	bodyFixed["status"] = "fixed"
	registerVulnerability(t, router, bodyFixed)
	bodyOther := validCreateBody("CVE-2024-0003")
	bodyOther["component"] = "LIBXML2"
	registerVulnerability(t, router, bodyOther)
	openssl := map[string]any{
		"id":        "CVE-2024-0010",
		"component": "openssl",
		"affected_ranges": []any{
			map[string]any{"lower": "1.0", "lower_include": true, "upper": "1.1", "upper_include": false},
		},
		"severity":      "critical",
		"fixed_version": "1.1.0",
		"status":        "open",
	}
	registerVulnerability(t, router, openssl)
	return router
}

func TestMatchVulnerabilitiesOrdersAndProjects(t *testing.T) {
	router := seedMatchRouter(t)

	body := matchBody(
		matchEntry("libxml2", "2.4.1"),
		matchEntry("openssl", "1.0.5"),
		matchEntry("libxml2", "9.9.9"),
		matchEntry("LIBXML2", "2.4.1"),
	)
	response := doMatch(t, router, body)
	if len(response.Results) != 4 {
		t.Fatalf("results = %d, want 4", len(response.Results))
	}

	first := response.Results[0]
	if first.Component != "libxml2" || first.Version != "2.4.1" {
		t.Fatalf("first echo wrong: %#v", first)
	}
	if len(first.Vulnerabilities) != 3 {
		t.Fatalf("first hits = %d, want 3: %#v", len(first.Vulnerabilities), first.Vulnerabilities)
	}
	wantIDs := []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0005"}
	for index, want := range wantIDs {
		if first.Vulnerabilities[index].ID != want {
			t.Fatalf("hit %d = %s, want %s", index, first.Vulnerabilities[index].ID, want)
		}
	}
	for _, hit := range first.Vulnerabilities {
		if hit.Component != "libxml2" {
			t.Fatalf("component projected wrong: %#v", hit)
		}
		if len(hit.MatchedRanges) != 1 || hit.MatchedRanges[0]["upper"] != "2.9" {
			t.Fatalf("matched_ranges must keep only the hit range in order: %#v", hit.MatchedRanges)
		}
		if hit.Severity == "" || hit.FixedVersion == "" || hit.Status == "" {
			t.Fatalf("projection missing fields: %#v", hit)
		}
	}
	fixedHit := first.Vulnerabilities[2]
	if fixedHit.ID != "CVE-2024-0005" || fixedHit.Status != "fixed" {
		t.Fatalf("fixed status must not be excluded: %#v", fixedHit)
	}

	second := response.Results[1]
	if second.Component != "openssl" || len(second.Vulnerabilities) != 1 ||
		second.Vulnerabilities[0].ID != "CVE-2024-0010" {
		t.Fatalf("openssl hit wrong: %#v", second)
	}
	if len(second.Vulnerabilities[0].MatchedRanges) != 1 ||
		second.Vulnerabilities[0].MatchedRanges[0]["lower"] != "1.0" {
		t.Fatalf("openssl matched_ranges wrong: %#v", second.Vulnerabilities[0].MatchedRanges)
	}

	if response.Results[2].Vulnerabilities == nil || len(response.Results[2].Vulnerabilities) != 0 {
		t.Fatalf("no-hit entry must carry an empty array: %#v", response.Results[2])
	}

	fourth := response.Results[3]
	if len(fourth.Vulnerabilities) != 1 || fourth.Vulnerabilities[0].ID != "CVE-2024-0003" {
		t.Fatalf("component match must stay case-sensitive: %#v", fourth)
	}
}

func TestMatchVulnerabilitiesDuplicatesHandledSeparately(t *testing.T) {
	router := seedMatchRouter(t)

	body := matchBody(
		matchEntry("libxml2", "2.0"),
		matchEntry("libxml2", "2.0"),
		matchEntry("libxml2", "2.9"),
	)
	response := doMatch(t, router, body)
	if len(response.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(response.Results))
	}
	for index, want := range []int{3, 3, 0} {
		if got := len(response.Results[index].Vulnerabilities); got != want {
			t.Fatalf("result %d hits = %d, want %d", index, got, want)
		}
	}
	if response.Results[0].Component != "libxml2" || response.Results[0].Version != "2.0" {
		t.Fatalf("echo wrong: %#v", response.Results[0])
	}
}

func TestMatchVulnerabilitiesVersionMissingSegmentsAreZero(t *testing.T) {
	router := seedMatchRouter(t)

	response := doMatch(t, router, matchBody(matchEntry("openssl", "1")))
	if len(response.Results) != 1 || len(response.Results[0].Vulnerabilities) != 1 {
		t.Fatalf("1 must equal 1.0.0 and hit: %#v", response.Results)
	}
}

func TestMatchVulnerabilitiesEmptyMatchesIsStableArray(t *testing.T) {
	router := seedMatchRouter(t)

	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/match",
		matchBody(matchEntry("unknown", "1.0")))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, recorder.Body.String())
	}
	if len(response.Results) != 1 || string(response.Results[0]) !=
		`{"component":"unknown","version":"1.0","vulnerabilities":[]}` {
		t.Fatalf("no-hit entry wrong: %s", recorder.Body.String())
	}
}

func TestMatchVulnerabilitiesIgnoresUnrelatedFields(t *testing.T) {
	router := seedMatchRouter(t)

	body := map[string]any{
		"components": []any{map[string]any{
			"component": "libxml2", "version": "2.4.1", "extra": "ignored",
		}},
		"note": "ignored",
	}
	response := doMatch(t, router, body)
	if len(response.Results) != 1 || len(response.Results[0].Vulnerabilities) != 3 {
		t.Fatalf("unrelated fields must be ignored: %#v", response)
	}
}

func TestMatchVulnerabilitiesInvalidInputs(t *testing.T) {
	router := seedMatchRouter(t)
	valid := matchEntry("libxml2", "2.4.1")

	many := make([]any, 101)
	for index := range many {
		many[index] = valid
	}
	hundred := make([]any, 100)
	for index := range hundred {
		hundred[index] = valid
	}

	cases := map[string]any{
		"not an object":          `[1,2,3]`,
		"malformed json":         `{"components":`,
		"empty body":             ``,
		"trailing token":         `{"components":[{"component":"a","version":"1"}]} {}`,
		"missing components":     map[string]any{},
		"components not array":   map[string]any{"components": "nope"},
		"components null":        map[string]any{"components": nil},
		"empty components":       matchBody(),
		"more than 100":          map[string]any{"components": many},
		"element not object":     map[string]any{"components": []any{[]any{"libxml2"}}},
		"element null":           map[string]any{"components": []any{nil}},
		"element scalar":         map[string]any{"components": []any{"libxml2"}},
		"missing component":      map[string]any{"components": []any{map[string]any{"version": "1.0"}}},
		"empty component":        matchBody(matchEntry("", "1.0")),
		"component not string":   map[string]any{"components": []any{map[string]any{"component": 42, "version": "1.0"}}},
		"missing version":        map[string]any{"components": []any{map[string]any{"component": "libxml2"}}},
		"empty version":          matchBody(matchEntry("libxml2", "")),
		"version not string":     map[string]any{"components": []any{map[string]any{"component": "libxml2", "version": 1}}},
		"bad version":            matchBody(matchEntry("libxml2", "1.x")),
		"dotted empty segment":   matchBody(matchEntry("libxml2", "1.")),
		"second element invalid": map[string]any{"components": []any{valid, matchEntry("libxml2", "bad")}},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			var recorder *httptest.ResponseRecorder
			switch value := payload.(type) {
			case string:
				recorder = doRaw(t, router, "/vulnerabilities/match", value)
			default:
				recorder = doJSON(t, router, http.MethodPost, "/vulnerabilities/match", value)
			}
			if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}

	ok := doJSON(t, router, http.MethodPost, "/vulnerabilities/match",
		map[string]any{"components": hundred})
	if ok.Code != http.StatusOK {
		t.Fatalf("100 entries must be accepted: status=%d body=%s", ok.Code, ok.Body.String())
	}
}

func TestMatchVulnerabilitiesStorageFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0020"))
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/match",
		matchBody(matchEntry("libxml2", "2.4.1")))
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
	if body := recorder.Body.String(); bytes.Contains([]byte(body), []byte("SQL")) ||
		bytes.Contains([]byte(body), []byte("goroutine")) {
		t.Fatalf("body leaks internals: %s", body)
	}
}

func TestMatchCoexistsWithExistingRoutes(t *testing.T) {
	router := seedMatchRouter(t)

	if recorder := doJSON(t, router, http.MethodGet,
		"/vulnerabilities/affected?component=libxml2&version=2.4.1", nil); recorder.Code != http.StatusOK {
		t.Fatalf("affected route changed: status=%d", recorder.Code)
	}
	if recorder := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-2024-0001", nil); recorder.Code != http.StatusOK {
		t.Fatalf("get route changed: status=%d", recorder.Code)
	}
}
