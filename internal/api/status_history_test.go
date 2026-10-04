package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type historyEvent struct {
	Sequence       int     `json:"sequence"`
	PreviousStatus *string `json:"previous_status"`
	Status         string  `json:"status"`
	Source         string  `json:"source"`
}

type historyResponse struct {
	ID       string         `json:"id"`
	Items    []historyEvent `json:"items"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
	Total    int            `json:"total"`
}

func fetchHistory(t *testing.T, router http.Handler, target string) historyResponse {
	t.Helper()
	recorder := doJSON(t, router, http.MethodGet, target, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("get %s status = %d body = %s", target, recorder.Code, recorder.Body.String())
	}
	var response historyResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v body = %s", err, recorder.Body.String())
	}
	return response
}

func requireHistoryEvent(t *testing.T, event historyEvent, sequence int, previous, status, source string) {
	t.Helper()
	if event.Sequence != sequence {
		t.Fatalf("sequence = %d, want %d", event.Sequence, sequence)
	}
	if previous == "" {
		if event.PreviousStatus != nil {
			t.Fatalf("previous_status = %q, want null", *event.PreviousStatus)
		}
	} else if event.PreviousStatus == nil || *event.PreviousStatus != previous {
		t.Fatalf("previous_status = %v, want %q", event.PreviousStatus, previous)
	}
	if event.Status != status || event.Source != source {
		t.Fatalf("event = (%q, %q), want (%q, %q)", event.Status, event.Source, status, source)
	}
}

func patchStatus(t *testing.T, router http.Handler, id, status string) {
	t.Helper()
	recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/status/"+id,
		map[string]any{"status": status})
	if recorder.Code != http.StatusOK {
		t.Fatalf("patch %s status = %d body = %s", id, recorder.Code, recorder.Body.String())
	}
}

func TestStatusHistoryAfterCreate(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-6001"))

	recorder := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-2024-6001/status-history", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	want := `{"id":"CVE-2024-6001","items":[{"sequence":1,"previous_status":null,"status":"open","source":"create"}],"page":1,"page_size":20,"total":1}`
	if recorder.Body.String() != want {
		t.Fatalf("body = %s, want %s", recorder.Body.String(), want)
	}
}

func TestStatusHistoryAcrossEntries(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-6002"))

	patchStatus(t, router, "CVE-2024-6002", "in_progress")

	recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses",
		statusesBody(map[string]any{"id": "CVE-2024-6002", "status": "fixed"}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("batch patch status = %d body = %s", recorder.Code, recorder.Body.String())
	}

	replace := validUpdateBody()
	replace["status"] = "accepted"
	recorder = doJSON(t, router, http.MethodPut, "/vulnerabilities/CVE-2024-6002", replace)
	if recorder.Code != http.StatusOK {
		t.Fatalf("put status = %d body = %s", recorder.Code, recorder.Body.String())
	}

	response := fetchHistory(t, router, "/vulnerabilities/CVE-2024-6002/status-history")
	if response.ID != "CVE-2024-6002" || response.Total != 4 || len(response.Items) != 4 {
		t.Fatalf("response = %+v", response)
	}
	requireHistoryEvent(t, response.Items[0], 1, "", "open", "create")
	requireHistoryEvent(t, response.Items[1], 2, "open", "in_progress", "status_update")
	requireHistoryEvent(t, response.Items[2], 3, "in_progress", "fixed", "status_update")
	requireHistoryEvent(t, response.Items[3], 4, "fixed", "accepted", "replace")
}

func TestStatusHistoryUnchangedUpdatesWriteNoEvents(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-6003"))

	patchStatus(t, router, "CVE-2024-6003", "open")

	recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses",
		statusesBody(map[string]any{"id": "CVE-2024-6003", "status": "open"}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("batch patch status = %d body = %s", recorder.Code, recorder.Body.String())
	}

	recorder = doJSON(t, router, http.MethodPut, "/vulnerabilities/CVE-2024-6003", validCreateBody("CVE-2024-6003"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("put status = %d body = %s", recorder.Code, recorder.Body.String())
	}

	response := fetchHistory(t, router, "/vulnerabilities/CVE-2024-6003/status-history")
	if response.Total != 1 || len(response.Items) != 1 {
		t.Fatalf("unchanged updates must not append events: %+v", response)
	}
}

func TestStatusHistoryPagination(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-6004"))
	for _, status := range []string{"in_progress", "fixed", "accepted", "open"} {
		patchStatus(t, router, "CVE-2024-6004", status)
	}

	response := fetchHistory(t, router, "/vulnerabilities/CVE-2024-6004/status-history?page=2&page_size=2")
	if response.Page != 2 || response.PageSize != 2 || response.Total != 5 || len(response.Items) != 2 {
		t.Fatalf("response = %+v", response)
	}
	if response.Items[0].Sequence != 3 || response.Items[1].Sequence != 4 {
		t.Fatalf("page 2 sequences = %d, %d, want 3, 4",
			response.Items[0].Sequence, response.Items[1].Sequence)
	}

	response = fetchHistory(t, router, "/vulnerabilities/CVE-2024-6004/status-history?page=3&page_size=2")
	if response.Total != 5 || len(response.Items) != 1 || response.Items[0].Sequence != 5 {
		t.Fatalf("last page = %+v", response)
	}

	recorder := doJSON(t, router, http.MethodGet,
		"/vulnerabilities/CVE-2024-6004/status-history?page=4&page_size=2", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"items":[]`) {
		t.Fatalf("past-end page must carry an empty array: %s", recorder.Body.String())
	}

	response = fetchHistory(t, router, "/vulnerabilities/CVE-2024-6004/status-history?page_size=100")
	if response.PageSize != 100 || response.Total != 5 || len(response.Items) != 5 {
		t.Fatalf("page_size=100 = %+v", response)
	}
}

func TestStatusHistoryInvalidPagination(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-6005"))

	targets := []string{
		"/vulnerabilities/CVE-2024-6005/status-history?page=0",
		"/vulnerabilities/CVE-2024-6005/status-history?page=-1",
		"/vulnerabilities/CVE-2024-6005/status-history?page=abc",
		"/vulnerabilities/CVE-2024-6005/status-history?page=1.5",
		"/vulnerabilities/CVE-2024-6005/status-history?page=",
		"/vulnerabilities/CVE-2024-6005/status-history?page_size=0",
		"/vulnerabilities/CVE-2024-6005/status-history?page_size=-2",
		"/vulnerabilities/CVE-2024-6005/status-history?page_size=xyz",
		"/vulnerabilities/CVE-2024-6005/status-history?page_size=101",
		"/vulnerabilities/CVE-2024-6005/status-history?page=2&page_size=1000",
		"/vulnerabilities/CVE-9999-0000/status-history?page=abc",
	}
	for _, target := range targets {
		recorder := doJSON(t, router, http.MethodGet, target, nil)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", target, recorder.Code)
		}
		if recorder.Body.String() != "error=INVALID_INPUT" {
			t.Fatalf("%s body = %s, want error=INVALID_INPUT", target, recorder.Body.String())
		}
	}
}

func TestStatusHistoryUnknownID(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-6006"))

	for _, target := range []string{
		"/vulnerabilities/CVE-9999-0000/status-history",
		"/vulnerabilities/cve-2024-6006/status-history",
	} {
		recorder := doJSON(t, router, http.MethodGet, target, nil)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", target, recorder.Code)
		}
		if recorder.Body.String() != "error=VULNERABILITY_NOT_FOUND" {
			t.Fatalf("%s body = %s, want error=VULNERABILITY_NOT_FOUND", target, recorder.Body.String())
		}
	}
}

func TestStatusHistoryBatchRollbackLeavesNoEvents(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-6007"))

	recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses", statusesBody(
		map[string]any{"id": "CVE-2024-6007", "status": "fixed"},
		map[string]any{"id": "CVE-9999-0000", "status": "fixed"},
	))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.String() != "error=VULNERABILITY_NOT_FOUND" {
		t.Fatalf("body = %s, want error=VULNERABILITY_NOT_FOUND", recorder.Body.String())
	}

	response := fetchHistory(t, router, "/vulnerabilities/CVE-2024-6007/status-history")
	if response.Total != 1 || len(response.Items) != 1 {
		t.Fatalf("rolled back batch must not append events: %+v", response)
	}
	record := loadRecord(t, router, "CVE-2024-6007")
	if record["status"] != "open" {
		t.Fatalf("rolled back batch must not change status: %v", record["status"])
	}
}
