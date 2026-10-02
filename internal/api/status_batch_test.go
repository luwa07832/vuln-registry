package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func statusUpdateBody(ids ...string) map[string]any {
	statuses := []string{"fixed", "in_progress", "wont_fix", "accepted", "open"}
	items := make([]any, 0, len(ids))
	for index, id := range ids {
		items = append(items, map[string]any{
			"id":     id,
			"status": statuses[index%len(statuses)],
		})
	}
	return map[string]any{"updates": items}
}

func doRawPatch(t *testing.T, router http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPatch, "/vulnerabilities/statuses", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestUpdateStatusesSuccessMirrorsOrder(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-0001"))
	registerVulnerability(t, router, validCreateBody("CVE-2024-0002"))
	registerVulnerability(t, router, validCreateBody("CVE-2024-0003"))

	body := map[string]any{"updates": []any{
		map[string]any{"id": "CVE-2024-0003", "status": "accepted", "ignored": "x"},
		map[string]any{"id": "CVE-2024-0001", "status": "fixed"},
		map[string]any{"id": "CVE-2024-0002", "status": "in_progress"},
	}, "extra": true}
	recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}

	var response struct {
		Items []struct {
			ID           string `json:"id"`
			Component    string `json:"component"`
			Severity     string `json:"severity"`
			FixedVersion string `json:"fixed_version"`
			Status       string `json:"status"`
			Ranges       []struct {
				Lower *string `json:"lower"`
			} `json:"affected_ranges"`
		} `json:"items"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, recorder.Body.String())
	}
	if response.Count != 3 || len(response.Items) != 3 {
		t.Fatalf("count/items wrong: count=%d items=%d", response.Count, len(response.Items))
	}
	want := []struct {
		id, status string
	}{
		{"CVE-2024-0003", "accepted"},
		{"CVE-2024-0001", "fixed"},
		{"CVE-2024-0002", "in_progress"},
	}
	for index, item := range want {
		got := response.Items[index]
		if got.ID != item.id || got.Status != item.status {
			t.Fatalf("item %d = (%s, %s), want (%s, %s)", index, got.ID, got.Status, item.id, item.status)
		}
		if got.Component != "libxml2" || got.Severity != "high" || got.FixedVersion != "2.10.0" {
			t.Fatalf("non-status fields changed for %s: %#v", item.id, got)
		}
		if len(got.Ranges) != 2 || got.Ranges[1].Lower != nil {
			t.Fatalf("ranges changed for %s: %#v", item.id, got.Ranges)
		}
	}
}

func TestUpdateStatusesQueriesReflectNewStatus(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-1001"))
	registerVulnerability(t, router, validCreateBody("CVE-2024-1002"))

	recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses", map[string]any{
		"updates": []any{
			map[string]any{"id": "CVE-2024-1001", "status": "fixed"},
			// Same status is legal as long as each id appears once.
			map[string]any{"id": "CVE-2024-1002", "status": "fixed"},
		},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}

	got := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-2024-1001", nil)
	if got.Code != http.StatusOK {
		t.Fatalf("get status = %d", got.Code)
	}
	var record map[string]any
	if err := json.Unmarshal(got.Body.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record["status"] != "fixed" {
		t.Fatalf("get status = %v, want fixed", record["status"])
	}

	listed := doJSON(t, router, http.MethodGet, "/vulnerabilities?status=fixed", nil)
	var page listResponseShape
	if err := json.Unmarshal(listed.Body.Bytes(), &page); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("fixed-filtered list wrong: %#v", page)
	}
	openList := doJSON(t, router, http.MethodGet, "/vulnerabilities?status=open", nil)
	var openPage listResponseShape
	if err := json.Unmarshal(openList.Body.Bytes(), &openPage); err != nil {
		t.Fatalf("unmarshal open list: %v", err)
	}
	if openPage.Total != 0 || len(openPage.Items) != 0 {
		t.Fatalf("open records must be gone from filter: %#v", openPage)
	}

	affected := doJSON(t, router, http.MethodGet,
		"/vulnerabilities/affected?component=libxml2&version=2.4.1", nil)
	var hits []map[string]any
	if err := json.Unmarshal(affected.Body.Bytes(), &hits); err != nil {
		t.Fatalf("unmarshal hits: %v", err)
	}
	if len(hits) != 2 || hits[0]["status"] != "fixed" {
		t.Fatalf("affected hits must carry new status: %#v", hits)
	}
}

func TestUpdateStatusesSingleEntryStillWorks(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-2001"))
	registerVulnerability(t, router, validCreateBody("CVE-2024-2002"))

	single := doJSON(t, router, http.MethodPatch,
		"/vulnerabilities/status/CVE-2024-2001", map[string]any{"status": "wont_fix"})
	if single.Code != http.StatusOK {
		t.Fatalf("single patch status = %d body = %s", single.Code, single.Body.String())
	}
	batch := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses",
		statusUpdateBody("CVE-2024-2002"))
	if batch.Code != http.StatusOK {
		t.Fatalf("batch patch status = %d body = %s", batch.Code, batch.Body.String())
	}

	for _, want := range []struct {
		id, status string
	}{{"CVE-2024-2001", "wont_fix"}, {"CVE-2024-2002", "fixed"}} {
		got := doJSON(t, router, http.MethodGet, "/vulnerabilities/"+want.id, nil)
		var record map[string]any
		if err := json.Unmarshal(got.Body.Bytes(), &record); err != nil {
			t.Fatalf("unmarshal %s: %v", want.id, err)
		}
		if record["status"] != want.status {
			t.Fatalf("%s status = %v, want %s", want.id, record["status"], want.status)
		}
	}
}

func TestUpdateStatusesInvalidInput(t *testing.T) {
	cases := map[string]string{
		"not an object":        `[1,2,3]`,
		"malformed json":       `{not json`,
		"missing updates":      `{"items":[]}`,
		"updates not array":    `{"updates":{}}`,
		"updates null":         `{"updates":null}`,
		"empty updates":        `{"updates":[]}`,
		"element not object":   `{"updates":[{"id":"CVE-1","status":"fixed"},"fixed"]}`,
		"missing id":           `{"updates":[{"status":"fixed"}]}`,
		"empty id":             `{"updates":[{"id":"","status":"fixed"}]}`,
		"missing status":       `{"updates":[{"id":"CVE-1"}]}`,
		"null status":          `{"updates":[{"id":"CVE-1","status":null}]}`,
		"bad status":           `{"updates":[{"id":"CVE-1","status":"closed"}]}`,
		"non-string status":    `{"updates":[{"id":"CVE-1","status":5}]}`,
		"duplicate ids":        `{"updates":[{"id":"CVE-1","status":"fixed"},{"id":"CVE-1","status":"open"}]}`,
		"two json values":      `{"updates":[]}{}`,
		"top-level json array": `[]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			router := newTestRouter(t)
			registerVulnerability(t, router, validCreateBody("CVE-1"))
			recorder := doRawPatch(t, router, body)
			if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
			got := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-1", nil)
			var record map[string]any
			if err := json.Unmarshal(got.Body.Bytes(), &record); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if record["status"] != "open" {
				t.Fatalf("record changed on failed validation: %v", record["status"])
			}
		})
	}

	t.Run("over 100 items", func(t *testing.T) {
		router := newTestRouter(t)
		var builder strings.Builder
		builder.WriteString(`{"updates":[`)
		for index := 0; index < 101; index++ {
			if index > 0 {
				builder.WriteByte(',')
			}
			fmt.Fprintf(&builder, `{"id":"CVE-%d","status":"fixed"}`, index)
		}
		builder.WriteString(`]}`)
		recorder := doRawPatch(t, router, builder.String())
		if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
			t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("exactly 100 items accepted structurally", func(t *testing.T) {
		router := newTestRouter(t)
		items := make([]any, 0, 100)
		for index := 0; index < 100; index++ {
			id := fmt.Sprintf("CVE-%03d", index)
			registerVulnerability(t, router, validCreateBody(id))
			items = append(items, map[string]any{"id": id, "status": "fixed"})
		}
		recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses",
			map[string]any{"updates": items})
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
		}
	})
}

func TestUpdateStatusesUnknownIdNotFoundAndAtomic(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-3001"))
	registerVulnerability(t, router, validCreateBody("CVE-2024-3002"))

	recorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses", map[string]any{
		"updates": []any{
			map[string]any{"id": "CVE-2024-3002", "status": "fixed"},
			map[string]any{"id": "CVE-MISSING", "status": "accepted"},
		},
	})
	if recorder.Code != http.StatusNotFound || recorder.Body.String() != "error=VULNERABILITY_NOT_FOUND" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	for _, id := range []string{"CVE-2024-3001", "CVE-2024-3002"} {
		got := doJSON(t, router, http.MethodGet, "/vulnerabilities/"+id, nil)
		var record map[string]any
		if err := json.Unmarshal(got.Body.Bytes(), &record); err != nil {
			t.Fatalf("unmarshal %s: %v", id, err)
		}
		if record["status"] != "open" {
			t.Fatalf("%s must stay open after 404 rollback, got %v", id, record["status"])
		}
	}

	caseRecorder := doJSON(t, router, http.MethodPatch, "/vulnerabilities/statuses", map[string]any{
		"updates": []any{map[string]any{"id": "cve-2024-3001", "status": "fixed"}},
	})
	if caseRecorder.Code != http.StatusNotFound || caseRecorder.Body.String() != "error=VULNERABILITY_NOT_FOUND" {
		t.Fatalf("case-sensitive match broken: status=%d body=%q",
			caseRecorder.Code, caseRecorder.Body.String())
	}
}
