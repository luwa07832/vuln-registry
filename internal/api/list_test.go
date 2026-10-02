package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/store"
)

type listRecordSpec struct {
	id        string
	component string
	severity  string
	status    string
}

func registerListRecord(t *testing.T, router http.Handler, spec listRecordSpec) {
	t.Helper()
	body := validCreateBody(spec.id)
	body["component"] = spec.component
	body["severity"] = spec.severity
	body["status"] = spec.status
	registerVulnerability(t, router, body)
}

func getListPage(t *testing.T, router http.Handler, target string) (int, map[string]any) {
	t.Helper()
	recorder := doJSON(t, router, http.MethodGet, target, nil)
	var response map[string]any
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("unmarshal %s: %v body=%s", target, err, recorder.Body.String())
		}
	}
	return recorder.Code, response
}

func listIDs(page map[string]any) []any {
	return page["items"].([]any)
}

func seedListDataset(t *testing.T, router http.Handler) {
	specs := []listRecordSpec{
		{"CVE-2024-0003", "libxml2", "high", "fixed"},
		{"CVE-2024-0001", "libxml2", "low", "open"},
		{"CVE-2024-0002", "libxml2", "high", "open"},
		{"CVE-2024-0004", "openssl", "critical", "in_progress"},
		{"CVE-2024-0005", "LIBXML2", "medium", "accepted"},
	}
	for _, spec := range specs {
		registerListRecord(t, router, spec)
	}
}

func TestListDefaultsSortAndEnvelope(t *testing.T) {
	router := newTestRouter(t)
	seedListDataset(t, router)

	code, page := getListPage(t, router, "/vulnerabilities")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if page["page"].(float64) != 1 || page["page_size"].(float64) != 20 || page["total"].(float64) != 5 {
		t.Fatalf("envelope defaults wrong: %v", page)
	}
	ids := listIDs(page)
	if len(ids) != 5 {
		t.Fatalf("items = %d, want 5: %v", len(ids), ids)
	}
	want := []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004", "CVE-2024-0005"}
	for i, item := range ids {
		if item.(map[string]any)["id"] != want[i] {
			t.Fatalf("items not id-sorted: %v", ids)
		}
	}
}

func TestListItemsAreFullRecords(t *testing.T) {
	router := newTestRouter(t)
	seedListDataset(t, router)

	_, page := getListPage(t, router, "/vulnerabilities?component=libxml2")
	items := listIDs(page)
	if len(items) != 3 {
		t.Fatalf("items = %d, want 3: %v", len(items), items)
	}
	first := items[0].(map[string]any)
	for _, key := range []string{"id", "component", "affected_ranges", "severity", "fixed_version", "status"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("item missing key %q: %v", key, first)
		}
	}
	ranges := first["affected_ranges"].([]any)
	if len(ranges) != 2 {
		t.Fatalf("affected_ranges = %v", first["affected_ranges"])
	}
	secondRange := ranges[1].(map[string]any)
	if secondRange["lower"] != nil || secondRange["lower_include"] != nil {
		t.Fatalf("open bounds must stay null: %v", secondRange)
	}
}

func TestListPaginationSlicesAndEcho(t *testing.T) {
	router := newTestRouter(t)
	seedListDataset(t, router)

	code, page := getListPage(t, router, "/vulnerabilities?page=2&page_size=2")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if page["page"].(float64) != 2 || page["page_size"].(float64) != 2 || page["total"].(float64) != 5 {
		t.Fatalf("envelope wrong: %v", page)
	}
	items := listIDs(page)
	if len(items) != 2 || items[0].(map[string]any)["id"] != "CVE-2024-0003" ||
		items[1].(map[string]any)["id"] != "CVE-2024-0004" {
		t.Fatalf("page 2 wrong: %v", items)
	}

	code, last := getListPage(t, router, "/vulnerabilities?page=3&page_size=2")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	lastItems := listIDs(last)
	if len(lastItems) != 1 || lastItems[0].(map[string]any)["id"] != "CVE-2024-0005" {
		t.Fatalf("last page wrong: %v", lastItems)
	}
	if last["total"].(float64) != 5 {
		t.Fatalf("total = %v", last["total"])
	}
}

func TestListPageBeyondRangeReturnsEmptyItems(t *testing.T) {
	router := newTestRouter(t)
	seedListDataset(t, router)

	code, page := getListPage(t, router, "/vulnerabilities?page=4&page_size=2")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(listIDs(page)) != 0 {
		t.Fatalf("items must be empty: %v", page["items"])
	}
	if page["page"].(float64) != 4 || page["page_size"].(float64) != 2 || page["total"].(float64) != 5 {
		t.Fatalf("envelope wrong: %v", page)
	}
}

func TestListEmptyStoreEnvelope(t *testing.T) {
	router := newTestRouter(t)

	code, page := getListPage(t, router, "/vulnerabilities")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if page["total"].(float64) != 0 || len(listIDs(page)) != 0 {
		t.Fatalf("empty page wrong: %v", page)
	}
	if page["page"].(float64) != 1 || page["page_size"].(float64) != 20 {
		t.Fatalf("defaults wrong: %v", page)
	}
	raw, _ := json.Marshal(page["items"])
	if string(raw) != "[]" {
		t.Fatalf("items must encode as [], got %s", raw)
	}
}

func TestListFiltersCombineAndIntersect(t *testing.T) {
	router := newTestRouter(t)
	seedListDataset(t, router)

	cases := []struct {
		target string
		want   []string
		total  float64
	}{
		{"/vulnerabilities?component=libxml2", []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}, 3},
		{"/vulnerabilities?component=LIBXML2", []string{"CVE-2024-0005"}, 1},
		{"/vulnerabilities?severity=high", []string{"CVE-2024-0002", "CVE-2024-0003"}, 2},
		{"/vulnerabilities?status=open", []string{"CVE-2024-0001", "CVE-2024-0002"}, 2},
		{"/vulnerabilities?component=libxml2&severity=high", []string{"CVE-2024-0002", "CVE-2024-0003"}, 2},
		{"/vulnerabilities?component=libxml2&status=fixed", []string{"CVE-2024-0003"}, 1},
		{"/vulnerabilities?severity=high&status=open", []string{"CVE-2024-0002"}, 1},
		{"/vulnerabilities?component=libxml2&severity=high&status=fixed", []string{"CVE-2024-0003"}, 1},
		{"/vulnerabilities?component=libxml2&severity=critical", nil, 0},
		{"/vulnerabilities?fixed_version=2.10.0", []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004", "CVE-2024-0005"}, 5},
	}
	for _, tc := range cases {
		code, page := getListPage(t, router, tc.target)
		if code != http.StatusOK {
			t.Fatalf("%s: status = %d", tc.target, code)
		}
		if page["total"] != tc.total {
			t.Fatalf("%s: total = %v, want %v", tc.target, page["total"], tc.total)
		}
		items := listIDs(page)
		if len(items) != len(tc.want) {
			t.Fatalf("%s: items = %v, want %v", tc.target, items, tc.want)
		}
		for i, item := range items {
			if item.(map[string]any)["id"] != tc.want[i] {
				t.Fatalf("%s: items = %v, want %v", tc.target, items, tc.want)
			}
		}
	}
}

func TestListReflectsStatusUpdate(t *testing.T) {
	router := newTestRouter(t)
	seedListDataset(t, router)

	updated := doJSON(t, router, http.MethodPatch,
		"/vulnerabilities/status/CVE-2024-0001", map[string]any{"status": "fixed"})
	if updated.Code != http.StatusOK {
		t.Fatalf("patch status = %d body = %s", updated.Code, updated.Body.String())
	}

	_, open := getListPage(t, router, "/vulnerabilities?status=open")
	if open["total"].(float64) != 1 || listIDs(open)[0].(map[string]any)["id"] != "CVE-2024-0002" {
		t.Fatalf("open page wrong after update: %v", open)
	}
	_, fixed := getListPage(t, router, "/vulnerabilities?component=libxml2&status=fixed")
	if fixed["total"].(float64) != 2 {
		t.Fatalf("fixed page wrong after update: %v", fixed)
	}
}

func TestListInvalidInputs(t *testing.T) {
	router := newTestRouter(t)
	seedListDataset(t, router)

	targets := []string{
		"/vulnerabilities?component=",
		"/vulnerabilities?severity=",
		"/vulnerabilities?severity=urgent",
		"/vulnerabilities?status=closed",
		"/vulnerabilities?status=",
		"/vulnerabilities?page=",
		"/vulnerabilities?page=0",
		"/vulnerabilities?page=-1",
		"/vulnerabilities?page=1.5",
		"/vulnerabilities?page=abc",
		"/vulnerabilities?page=01",
		"/vulnerabilities?page_size=",
		"/vulnerabilities?page_size=0",
		"/vulnerabilities?page_size=101",
		"/vulnerabilities?page_size=20.0",
		"/vulnerabilities?page=1&page_size=0",
		"/vulnerabilities?component=libxml2&severity=bad",
	}
	for _, target := range targets {
		recorder := doJSON(t, router, http.MethodGet, target, nil)
		if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
			t.Fatalf("%s: status=%d body=%q", target, recorder.Code, recorder.Body.String())
		}
		if contentType := recorder.Header().Get("Content-Type"); contentType != "text/plain; charset=utf-8" {
			t.Fatalf("%s: content-type = %q", target, contentType)
		}
	}
}

func TestListUnknownParamsAndBoundarySizes(t *testing.T) {
	router := newTestRouter(t)
	seedListDataset(t, router)

	code, page := getListPage(t, router, "/vulnerabilities?whatever=1&foo=")
	if code != http.StatusOK || page["total"].(float64) != 5 {
		t.Fatalf("unknown params must be ignored: code=%d page=%v", code, page)
	}

	code, sized := getListPage(t, router, "/vulnerabilities?page=1&page_size=100")
	if code != http.StatusOK || sized["page_size"].(float64) != 100 {
		t.Fatalf("page_size=100 must be accepted: %d %v", code, sized)
	}
	code, one := getListPage(t, router, "/vulnerabilities?page=1&page_size=1")
	if code != http.StatusOK || len(listIDs(one)) != 1 || one["total"].(float64) != 5 {
		t.Fatalf("page_size=1 wrong: %d %v", code, one)
	}
}

func TestListStorageFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0020"))
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
	if !ok || errorBody["code"] != "internal_error" || errorBody["message"] != "request could not be completed" {
		t.Fatalf("error body wrong: %v", response)
	}
}
