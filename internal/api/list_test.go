package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/store"
)

type listTestItem struct {
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

type listTestResponse struct {
	Items    []listTestItem `json:"items"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
	Total    int            `json:"total"`
}

func listCreateBody(id, component, severity, status string) map[string]any {
	body := validCreateBody(id)
	body["component"] = component
	body["severity"] = severity
	body["status"] = status
	return body
}

func seedListRouter(t *testing.T) http.Handler {
	t.Helper()
	router := newTestRouter(t)
	registerVulnerability(t, router, listCreateBody("CVE-2024-0003", "libxml2", "high", "open"))
	registerVulnerability(t, router, listCreateBody("CVE-2024-0001", "libxml2", "low", "fixed"))
	registerVulnerability(t, router, listCreateBody("CVE-2024-0002", "openssl", "high", "open"))
	registerVulnerability(t, router, listCreateBody("CVE-2024-0004", "libxml2", "high", "wont_fix"))
	return router
}

func doList(t *testing.T, router http.Handler, target string) listTestResponse {
	t.Helper()
	recorder := doJSON(t, router, http.MethodGet, target, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d body = %s", target, recorder.Code, recorder.Body.String())
	}
	var response listTestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("GET %s: unmarshal: %v body=%s", target, err, recorder.Body.String())
	}
	return response
}

func itemIDs(items []listTestItem) []string {
	ids := []string{}
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	return ids
}

func assertIDs(t *testing.T, items []listTestItem, want []string) {
	t.Helper()
	got := itemIDs(items)
	if len(got) != len(want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("ids = %v, want %v", got, want)
		}
	}
}

func TestListVulnerabilitiesDefaultsAndFullRecords(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0002"))
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))

	response := doList(t, router, "/vulnerabilities")
	if response.Page != 1 || response.PageSize != 20 || response.Total != 2 {
		t.Fatalf("page fields = %+v", response)
	}
	assertIDs(t, response.Items, []string{"CVE-2024-0001", "CVE-2024-0002"})

	item := response.Items[0]
	if item.Component != "libxml2" || item.Severity != "high" ||
		item.FixedVersion != "2.10.0" || item.Status != "open" {
		t.Fatalf("scalar fields wrong: %+v", item)
	}
	if len(item.Ranges) != 2 {
		t.Fatalf("ranges = %d, want 2", len(item.Ranges))
	}
	if item.Ranges[0].Lower == nil || *item.Ranges[0].Lower != "2.0" ||
		item.Ranges[0].Upper == nil || *item.Ranges[0].Upper != "2.9" {
		t.Fatalf("first range wrong: %+v", item.Ranges[0])
	}
	if item.Ranges[1].Lower != nil || item.Ranges[1].Upper == nil || *item.Ranges[1].Upper != "1.5.0" {
		t.Fatalf("open bound must serialize as null: %+v", item.Ranges[1])
	}
}

func TestListVulnerabilitiesFiltersIntersect(t *testing.T) {
	router := seedListRouter(t)

	response := doList(t, router, "/vulnerabilities?component=libxml2")
	if response.Total != 3 {
		t.Fatalf("total = %d, want 3", response.Total)
	}
	assertIDs(t, response.Items, []string{"CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0004"})

	response = doList(t, router, "/vulnerabilities?component=LIBXML2")
	if response.Total != 0 || len(response.Items) != 0 {
		t.Fatalf("component match must be case-sensitive: %+v", response)
	}

	response = doList(t, router, "/vulnerabilities?severity=high")
	if response.Total != 3 {
		t.Fatalf("total = %d, want 3", response.Total)
	}
	assertIDs(t, response.Items, []string{"CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"})

	response = doList(t, router, "/vulnerabilities?status=open")
	if response.Total != 2 {
		t.Fatalf("total = %d, want 2", response.Total)
	}
	assertIDs(t, response.Items, []string{"CVE-2024-0002", "CVE-2024-0003"})

	response = doList(t, router, "/vulnerabilities?component=libxml2&severity=high&status=wont_fix")
	if response.Total != 1 {
		t.Fatalf("total = %d, want 1", response.Total)
	}
	assertIDs(t, response.Items, []string{"CVE-2024-0004"})

	response = doList(t, router, "/vulnerabilities?component=libxml2&status=open&severity=low")
	if response.Total != 0 || len(response.Items) != 0 {
		t.Fatalf("contradicting filters must intersect to empty: %+v", response)
	}
}

func TestListVulnerabilitiesPaginates(t *testing.T) {
	router := seedListRouter(t)

	response := doList(t, router, "/vulnerabilities?page_size=2")
	if response.Page != 1 || response.PageSize != 2 || response.Total != 4 {
		t.Fatalf("page fields = %+v", response)
	}
	assertIDs(t, response.Items, []string{"CVE-2024-0001", "CVE-2024-0002"})

	response = doList(t, router, "/vulnerabilities?page=2&page_size=2")
	if response.Page != 2 || response.PageSize != 2 || response.Total != 4 {
		t.Fatalf("page fields = %+v", response)
	}
	assertIDs(t, response.Items, []string{"CVE-2024-0003", "CVE-2024-0004"})

	response = doList(t, router, "/vulnerabilities?page=2&page_size=3")
	if response.Page != 2 || response.PageSize != 3 || response.Total != 4 {
		t.Fatalf("page fields = %+v", response)
	}
	assertIDs(t, response.Items, []string{"CVE-2024-0004"})

	recorder := doJSON(t, router, http.MethodGet, "/vulnerabilities?page=5&page_size=2", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("overflow page must not be 404: status = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"items":[]`) {
		t.Fatalf("overflow page items must be an empty array: %s", recorder.Body.String())
	}
	response = doList(t, router, "/vulnerabilities?page=5&page_size=2")
	if response.Page != 5 || response.PageSize != 2 || response.Total != 4 || len(response.Items) != 0 {
		t.Fatalf("overflow page wrong: %+v", response)
	}
}

func TestListVulnerabilitiesEmptyResultIsNotFoundError(t *testing.T) {
	router := newTestRouter(t)
	recorder := doJSON(t, router, http.MethodGet, "/vulnerabilities?status=accepted", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"items":[]`) {
		t.Fatalf("items must be an empty array: %s", recorder.Body.String())
	}
	response := doList(t, router, "/vulnerabilities?status=accepted")
	if response.Page != 1 || response.PageSize != 20 || response.Total != 0 {
		t.Fatalf("page fields = %+v", response)
	}
}

func TestListVulnerabilitiesInvalidInputs(t *testing.T) {
	router := seedListRouter(t)
	targets := []string{
		"/vulnerabilities?component=",
		"/vulnerabilities?severity=extreme",
		"/vulnerabilities?severity=",
		"/vulnerabilities?severity=HIGH",
		"/vulnerabilities?status=unknown",
		"/vulnerabilities?status=",
		"/vulnerabilities?page=0",
		"/vulnerabilities?page=-1",
		"/vulnerabilities?page=abc",
		"/vulnerabilities?page=1.5",
		"/vulnerabilities?page=",
		"/vulnerabilities?page=+2",
		"/vulnerabilities?page=%202",
		"/vulnerabilities?page_size=0",
		"/vulnerabilities?page_size=101",
		"/vulnerabilities?page_size=-5",
		"/vulnerabilities?page_size=abc",
		"/vulnerabilities?page_size=",
	}
	for _, target := range targets {
		recorder := doJSON(t, router, http.MethodGet, target, nil)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("GET %s: status = %d, want 400", target, recorder.Code)
		}
		if body := recorder.Body.String(); body != "error=INVALID_INPUT" {
			t.Fatalf("GET %s: body = %q", target, body)
		}
	}
}

func TestListVulnerabilitiesIgnoresUnknownParams(t *testing.T) {
	router := seedListRouter(t)
	response := doList(t, router, "/vulnerabilities?foo=bar&fixed_version=2.10.0&sort=desc")
	if response.Total != 4 || len(response.Items) != 4 {
		t.Fatalf("unknown params must be ignored: %+v", response)
	}
}

func TestListVulnerabilitiesReflectsStatusUpdates(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))

	response := doList(t, router, "/vulnerabilities?status=open")
	if response.Total != 1 {
		t.Fatalf("total = %d, want 1", response.Total)
	}

	recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/status/CVE-2024-0001", map[string]any{"status": "fixed"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("patch status = %d body = %s", recorder.Code, recorder.Body.String())
	}

	response = doList(t, router, "/vulnerabilities?status=open")
	if response.Total != 0 || len(response.Items) != 0 {
		t.Fatalf("updated record must leave open filter: %+v", response)
	}
	response = doList(t, router, "/vulnerabilities?status=fixed")
	if response.Total != 1 || response.Items[0].Status != "fixed" {
		t.Fatalf("updated record must appear under fixed: %+v", response)
	}
}

func TestListVulnerabilitiesExcludesFailedRegistrations(t *testing.T) {
	router := newTestRouter(t)

	invalid := validCreateBody("CVE-2024-0001")
	invalid["severity"] = "extreme"
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities", invalid)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid create status = %d", recorder.Code)
	}
	response := doList(t, router, "/vulnerabilities")
	if response.Total != 0 || len(response.Items) != 0 {
		t.Fatalf("failed registration must not be listed: %+v", response)
	}

	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))
	duplicate := doJSON(t, router, http.MethodPost, "/vulnerabilities", validCreateBody("CVE-2024-0001"))
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate create status = %d", duplicate.Code)
	}
	response = doList(t, router, "/vulnerabilities")
	if response.Total != 1 {
		t.Fatalf("total = %d, want 1", response.Total)
	}
}

func TestListVulnerabilitiesStorageFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recorder := doJSON(t, router, http.MethodGet, "/vulnerabilities", nil)
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
}
