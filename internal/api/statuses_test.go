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

func doRawPatch(t *testing.T, router http.Handler, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPatch, target, bytes.NewReader([]byte(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func statusesBody(updates ...map[string]any) map[string]any {
	items := make([]any, 0, len(updates))
	for _, update := range updates {
		items = append(items, update)
	}
	return map[string]any{"updates": items}
}

func statusesBodyForCount(count int) string {
	items := make([]string, 0, count)
	for index := 0; index < count; index++ {
		items = append(items, fmt.Sprintf(`{"id":"CVE-2024-%04d","status":"fixed"}`, index))
	}
	return `{"updates":[` + strings.Join(items, ",") + `]}`
}

func loadRecord(t *testing.T, router http.Handler, id string) map[string]any {
	t.Helper()
	recorder := doJSON(t, router, http.MethodGet, "/vulnerabilities/"+id, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("get %s status = %d", id, recorder.Code)
	}
	var record map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal %s: %v", id, err)
	}
	return record
}

func TestUpdateStatusesSuccess(t *testing.T) {
	router := newTestRouter(t)
	for _, id := range []string{"CVE-2024-2001", "CVE-2024-2002", "CVE-2024-2003"} {
		registerVulnerability(t, router, validCreateBody(id))
	}

	body := statusesBody(
		map[string]any{"id": "CVE-2024-2003", "status": "fixed", "ignored": 1},
		map[string]any{"id": "CVE-2024-2001", "status": "accepted"},
	)
	body["extra"] = "ignored"
	recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Items []struct {
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
		} `json:"items"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, recorder.Body.String())
	}
	if response.Count != 2 || len(response.Items) != 2 {
		t.Fatalf("count/items wrong: count=%d items=%d", response.Count, len(response.Items))
	}
	if response.Items[0].ID != "CVE-2024-2003" || response.Items[1].ID != "CVE-2024-2001" {
		t.Fatalf("items must follow request order: %#v", response.Items)
	}
	if response.Items[0].Status != "fixed" || response.Items[1].Status != "accepted" {
		t.Fatalf("statuses wrong: %#v", response.Items)
	}
	first := response.Items[0]
	if first.Component != "libxml2" || first.Severity != "high" || first.FixedVersion != "2.10.0" {
		t.Fatalf("other fields must stay intact: %#v", first)
	}
	if len(first.Ranges) != 2 || first.Ranges[0].Lower == nil || *first.Ranges[0].Lower != "2.0" ||
		first.Ranges[1].Lower != nil || first.Ranges[1].Upper == nil || *first.Ranges[1].Upper != "1.5.0" {
		t.Fatalf("ranges must keep registration order and open bounds: %#v", first.Ranges)
	}

	if record := loadRecord(t, router, "CVE-2024-2002"); record["status"] != "open" {
		t.Fatalf("unlisted record changed: %v", record)
	}
}

func TestUpdateStatusesReflectedInQueries(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-2010"))

	recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses",
		statusesBody(map[string]any{"id": "CVE-2024-2010", "status": "wont_fix"}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}

	if record := loadRecord(t, router, "CVE-2024-2010"); record["status"] != "wont_fix" {
		t.Fatalf("get by id not updated: %v", record)
	}

	listed := doJSON(t, router, http.MethodGet, "/vulnerabilities?status=wont_fix", nil)
	var page listTestResponse
	if err := json.Unmarshal(listed.Body.Bytes(), &page); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != "CVE-2024-2010" {
		t.Fatalf("list filter not updated: %+v", page)
	}

	affected := doJSON(t, router, http.MethodGet, "/vulnerabilities/affected?component=libxml2&version=2.5", nil)
	var hits []map[string]any
	if err := json.Unmarshal(affected.Body.Bytes(), &hits); err != nil {
		t.Fatalf("unmarshal affected: %v", err)
	}
	if len(hits) != 1 || hits[0]["status"] != "wont_fix" {
		t.Fatalf("affected query not updated: %v", hits)
	}

	matched := doJSON(t, router, http.MethodPost, "/vulnerabilities/match",
		map[string]any{"components": []map[string]any{{"component": "libxml2", "version": "2.5"}}})
	var matchResponse struct {
		Results []struct {
			Vulnerabilities []map[string]any `json:"vulnerabilities"`
		} `json:"results"`
	}
	if err := json.Unmarshal(matched.Body.Bytes(), &matchResponse); err != nil {
		t.Fatalf("unmarshal match: %v", err)
	}
	if len(matchResponse.Results) != 1 || len(matchResponse.Results[0].Vulnerabilities) != 1 ||
		matchResponse.Results[0].Vulnerabilities[0]["status"] != "wont_fix" {
		t.Fatalf("match query not updated: %+v", matchResponse)
	}

	ranged := doJSON(t, router, http.MethodPost, "/vulnerabilities/range-match",
		map[string]any{"queries": []map[string]any{{
			"component": "libxml2", "lower": "2.1", "upper": "2.5",
			"lower_include": true, "upper_include": true,
		}}})
	var rangeResponse struct {
		Results []struct {
			Vulnerabilities []map[string]any `json:"vulnerabilities"`
		} `json:"results"`
	}
	if err := json.Unmarshal(ranged.Body.Bytes(), &rangeResponse); err != nil {
		t.Fatalf("unmarshal range match: %v", err)
	}
	if len(rangeResponse.Results) != 1 || len(rangeResponse.Results[0].Vulnerabilities) != 1 ||
		rangeResponse.Results[0].Vulnerabilities[0]["status"] != "wont_fix" {
		t.Fatalf("range match not updated: %+v", rangeResponse)
	}
}

func TestUpdateStatusesInvalidInput(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-2020"))

	bodies := []string{
		`[]`,
		`"updates"`,
		`{}`,
		`null`,
		`{"updates":null}`,
		`{"updates":{}}`,
		`{"updates":"CVE-2024-2020"}`,
		`{"updates":[]}`,
		statusesBodyForCount(101),
		`{"updates":["CVE-2024-2020"]}`,
		`{"updates":[null]}`,
		`{"updates":[1]}`,
		`{"updates":[{"status":"fixed"}]}`,
		`{"updates":[{"id":"","status":"fixed"}]}`,
		`{"updates":[{"id":"CVE-2024-2020"}]}`,
		`{"updates":[{"id":"CVE-2024-2020","status":""}]}`,
		`{"updates":[{"id":"CVE-2024-2020","status":"closed"}]}`,
		`{"updates":[{"id":"CVE-2024-2020","status":"FIXED"}]}`,
		`{"updates":[{"id":"CVE-2024-2020","status":"fixed"},{"id":"CVE-2024-2020","status":"open"}]}`,
		`{"updates":[{"id":"CVE-2024-2020","status":"fixed"}]} {"updates":[]}`,
	}
	for _, body := range bodies {
		recorder := doRawPatch(t, router, "/vulnerabilities/statuses", body)
		if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
			t.Fatalf("%s: status=%d body=%q", body, recorder.Code, recorder.Body.String())
		}
	}

	if record := loadRecord(t, router, "CVE-2024-2020"); record["status"] != "open" {
		t.Fatalf("invalid requests must not change anything: %v", record)
	}
}

func TestUpdateStatusesUnknownID(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-2030"))

	bodies := []map[string]any{
		statusesBody(map[string]any{"id": "CVE-9999-0000", "status": "fixed"}),
		statusesBody(
			map[string]any{"id": "CVE-2024-2030", "status": "fixed"},
			map[string]any{"id": "CVE-9999-0000", "status": "open"},
		),
		statusesBody(
			map[string]any{"id": "CVE-9999-0000", "status": "open"},
			map[string]any{"id": "CVE-9999-0001", "status": "fixed"},
		),
		statusesBody(map[string]any{"id": "cve-2024-2030", "status": "fixed"}),
	}
	for _, body := range bodies {
		recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses", body)
		if recorder.Code != http.StatusNotFound || recorder.Body.String() != "error=VULNERABILITY_NOT_FOUND" {
			t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
		}
	}

	if record := loadRecord(t, router, "CVE-2024-2030"); record["status"] != "open" {
		t.Fatalf("failed batches must not change anything: %v", record)
	}
}

func TestUpdateStatusesAcceptsHundredUpdates(t *testing.T) {
	router := newTestRouter(t)
	updates := make([]map[string]any, 0, 100)
	for index := 0; index < 100; index++ {
		id := fmt.Sprintf("CVE-2024-3%03d", index)
		registerVulnerability(t, router, validCreateBody(id))
		updates = append(updates, map[string]any{"id": id, "status": "fixed"})
	}

	recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses", statusesBody(updates...))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Items []map[string]any `json:"items"`
		Count int              `json:"count"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if response.Count != 100 || len(response.Items) != 100 {
		t.Fatalf("count = %d items = %d, want 100", response.Count, len(response.Items))
	}
}

func TestUpdateStatusesKeepsSinglePatchIndependent(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-2050"))
	registerVulnerability(t, router, validCreateBody("CVE-2024-2051"))

	batch := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses",
		statusesBody(map[string]any{"id": "CVE-2024-2050", "status": "in_progress"}))
	if batch.Code != http.StatusOK {
		t.Fatalf("batch status = %d body = %s", batch.Code, batch.Body.String())
	}

	single := doJSON(t, router, http.MethodPatch, "/vulnerabilities/status/CVE-2024-2051",
		map[string]any{"status": "accepted"})
	if single.Code != http.StatusOK {
		t.Fatalf("single status = %d body = %s", single.Code, single.Body.String())
	}
	var record map[string]any
	if err := json.Unmarshal(single.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record["status"] != "accepted" {
		t.Fatalf("single patch broken: %v", record)
	}

	if stored := loadRecord(t, router, "CVE-2024-2050"); stored["status"] != "in_progress" {
		t.Fatalf("single patch must not touch batch-updated record: %v", stored)
	}
}

func TestUpdateStatusesStorageFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)
	registerVulnerability(t, router, validCreateBody("CVE-2024-2040"))
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses",
		statusesBody(map[string]any{"id": "CVE-2024-2040", "status": "fixed"}))
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
