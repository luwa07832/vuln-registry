package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func strPtr(value string) *string { return &value }

func createHistoryVulnerability(t *testing.T, router http.Handler, id string) {
	t.Helper()
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities", validCreateBody(id))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}

func decodeHistory(t *testing.T, recorder *httptest.ResponseRecorder) struct {
	ID    string `json:"id"`
	Items []struct {
		Sequence       int     `json:"sequence"`
		PreviousStatus *string `json:"previous_status"`
		Status         string  `json:"status"`
		Source         string  `json:"source"`
	} `json:"items"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
} {
	t.Helper()
	var response struct {
		ID    string `json:"id"`
		Items []struct {
			Sequence       int     `json:"sequence"`
			PreviousStatus *string `json:"previous_status"`
			Status         string  `json:"status"`
			Source         string  `json:"source"`
		} `json:"items"`
		Page     int `json:"page"`
		PageSize int `json:"page_size"`
		Total    int `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, recorder.Body.String())
	}
	return response
}

func TestStatusHistoryInitialEvent(t *testing.T) {
	router := newTestRouter(t)
	createHistoryVulnerability(t, router, "CVE-2024-2001")

	recorder := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-2024-2001/status-history", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	response := decodeHistory(t, recorder)
	if response.ID != "CVE-2024-2001" || response.Page != 1 || response.PageSize != 20 || response.Total != 1 {
		t.Fatalf("envelope wrong: %#v", response)
	}
	if len(response.Items) != 1 {
		t.Fatalf("items len = %d, want 1", len(response.Items))
	}
	event := response.Items[0]
	if event.Sequence != 1 || event.Status != "open" || event.Source != "create" || event.PreviousStatus != nil {
		t.Fatalf("initial event wrong: %#v", event)
	}
}

func TestStatusHistoryEventsAcrossEntries(t *testing.T) {
	router := newTestRouter(t)
	createHistoryVulnerability(t, router, "CVE-2024-2002")

	patch := func(uri string, status string) {
		t.Helper()
		recorder := doJSON(t, router, http.MethodPatch, uri, map[string]any{"status": status})
		if recorder.Code != http.StatusOK {
			t.Fatalf("patch %s status = %d body = %s", uri, recorder.Code, recorder.Body.String())
		}
	}
	patch("/vulnerabilities/status/CVE-2024-2002", "fixed")
	patch("/vulnerabilities/status/CVE-2024-2002", "fixed")

	batch := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses", map[string]any{
		"updates": []map[string]any{{"id": "CVE-2024-2002", "status": "accepted"}},
	})
	if batch.Code != http.StatusOK {
		t.Fatalf("batch status = %d body = %s", batch.Code, batch.Body.String())
	}

	body := validCreateBody("CVE-2024-2002")
	body["status"] = "wont_fix"
	put := doJSON(t, router, http.MethodPut, "/vulnerabilities/CVE-2024-2002", body)
	if put.Code != http.StatusOK {
		t.Fatalf("put status = %d body = %s", put.Code, put.Body.String())
	}

	recorder := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-2024-2002/status-history", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	response := decodeHistory(t, recorder)
	if response.Total != 4 {
		t.Fatalf("total = %d, want 4", response.Total)
	}
	wantSources := []string{"create", "status_update", "status_update", "replace"}
	wantStatuses := []string{"open", "fixed", "accepted", "wont_fix"}
	wantPrevious := []*string{nil, strPtr("open"), strPtr("fixed"), strPtr("accepted")}
	for index := range wantSources {
		event := response.Items[index]
		if event.Sequence != index+1 {
			t.Fatalf("event %d sequence = %d", index, event.Sequence)
		}
		if event.Source != wantSources[index] || event.Status != wantStatuses[index] {
			t.Fatalf("event %d wrong: %#v", index, event)
		}
		if (event.PreviousStatus == nil) != (wantPrevious[index] == nil) ||
			wantPrevious[index] != nil && *event.PreviousStatus != *wantPrevious[index] {
			t.Fatalf("event %d previous = %v want %v", index, event.PreviousStatus, wantPrevious[index])
		}
	}
}

func TestStatusHistoryPaginationEchoesParams(t *testing.T) {
	router := newTestRouter(t)
	createHistoryVulnerability(t, router, "CVE-2024-2003")
	for _, status := range []string{"fixed", "accepted", "wont_fix"} {
		recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/status/CVE-2024-2003",
			map[string]any{"status": status})
		if recorder.Code != http.StatusOK {
			t.Fatalf("patch %s status = %d", status, recorder.Code)
		}
	}

	recorder := doJSON(t, router, http.MethodGet,
		"/vulnerabilities/CVE-2024-2003/status-history?page=2&page_size=2", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	response := decodeHistory(t, recorder)
	if response.Page != 2 || response.PageSize != 2 || response.Total != 4 {
		t.Fatalf("envelope wrong: %#v", response)
	}
	if len(response.Items) != 2 || response.Items[0].Sequence != 3 || response.Items[1].Sequence != 4 {
		t.Fatalf("page contents wrong: %#v", response.Items)
	}

	pastEnd := doJSON(t, router, http.MethodGet,
		"/vulnerabilities/CVE-2024-2003/status-history?page=99", nil)
	if pastEnd.Code != http.StatusOK {
		t.Fatalf("past end status = %d", pastEnd.Code)
	}
	pastResponse := decodeHistory(t, pastEnd)
	if pastResponse.Total != 4 || len(pastResponse.Items) != 0 || pastResponse.Page != 99 {
		t.Fatalf("past end payload wrong: %#v", pastResponse)
	}
}

func TestStatusHistoryCaseSensitiveAndUnknown(t *testing.T) {
	router := newTestRouter(t)
	createHistoryVulnerability(t, router, "CVE-2024-2004")

	for _, target := range []string{
		"/vulnerabilities/cve-2024-2004/status-history",
		"/vulnerabilities/CVE-2024-9999/status-history",
	} {
		recorder := doJSON(t, router, http.MethodGet, target, nil)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", target, recorder.Code)
		}
		if body := recorder.Body.String(); body != "error=VULNERABILITY_NOT_FOUND" {
			t.Fatalf("%s body = %q", target, body)
		}
	}
}

func TestStatusHistoryInvalidPagination(t *testing.T) {
	router := newTestRouter(t)
	createHistoryVulnerability(t, router, "CVE-2024-2005")

	for _, query := range []string{
		"page=0",
		"page=-1",
		"page=1.5",
		"page=abc",
		"page_size=0",
		"page_size=101",
		"page_size=two",
	} {
		recorder := doJSON(t, router, http.MethodGet,
			"/vulnerabilities/CVE-2024-2005/status-history?"+query, nil)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", query, recorder.Code)
		}
		if body := recorder.Body.String(); body != "error=INVALID_INPUT" {
			t.Fatalf("%s body = %q", query, body)
		}
	}
}

func TestStatusHistoryUnknownIDWithInvalidPagination(t *testing.T) {
	router := newTestRouter(t)
	recorder := doJSON(t, router, http.MethodGet,
		"/vulnerabilities/CVE-2024-4040/status-history?page=0", nil)
	if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
		t.Fatalf("invalid paging must beat unknown id: %d %q", recorder.Code, recorder.Body.String())
	}
}
