package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

func batchCreateBody(ids ...string) map[string]any {
	entries := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, validCreateBody(id))
	}
	return map[string]any{"vulnerabilities": entries}
}

func TestBatchCreateSuccessOrderProjectionAndCount(t *testing.T) {
	router := newTestRouter(t)
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch",
		batchCreateBody("CVE-2024-1002", "CVE-2024-1001"))

	if recorder.Code != http.StatusCreated {
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
	if response.Count != 2 {
		t.Fatalf("count = %d, want 2", response.Count)
	}
	if len(response.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(response.Items))
	}
	if response.Items[0].ID != "CVE-2024-1002" || response.Items[1].ID != "CVE-2024-1001" {
		t.Fatalf("items must mirror input order: %q %q", response.Items[0].ID, response.Items[1].ID)
	}
	first := response.Items[0]
	if first.Component != "libxml2" || first.Severity != "high" ||
		first.FixedVersion != "2.10.0" || first.Status != "open" {
		t.Fatalf("scalar projection wrong: %#v", first)
	}
	if len(first.Ranges) != 2 || first.Ranges[0].Lower == nil || *first.Ranges[0].Lower != "2.0" {
		t.Fatalf("ranges wrong: %#v", first.Ranges)
	}
	if first.Ranges[1].Lower != nil || first.Ranges[1].LowerInclude != nil {
		t.Fatalf("open lower bound must serialize as null: %#v", first.Ranges[1])
	}

	// Both records must be readable afterwards.
	for _, id := range []string{"CVE-2024-1001", "CVE-2024-1002"} {
		fetched := doJSON(t, router, http.MethodGet, "/vulnerabilities/"+id, nil)
		if fetched.Code != http.StatusOK {
			t.Fatalf("get %s: status=%d", id, fetched.Code)
		}
	}
}

func TestBatchCreateIgnoresUnknownFields(t *testing.T) {
	router := newTestRouter(t)
	body := batchCreateBody("CVE-2024-1100")
	body["extra_top"] = "ignored"
	entry := body["vulnerabilities"].([]map[string]any)[0]
	entry["extra_record"] = 42
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch", body)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestBatchCreateInvalidInputs(t *testing.T) {
	cases := map[string]func(map[string]any){
		"missing vulnerabilities field": func(b map[string]any) { delete(b, "vulnerabilities") },
		"empty array":                   func(b map[string]any) { b["vulnerabilities"] = []any{} },
		"null array":                    func(b map[string]any) { b["vulnerabilities"] = nil },
		"non-array field":               func(b map[string]any) { b["vulnerabilities"] = "nope" },
		"missing id in record":          func(b map[string]any) { delete(b["vulnerabilities"].([]map[string]any)[0], "id") },
		"empty component in record":     func(b map[string]any) { b["vulnerabilities"].([]map[string]any)[0]["component"] = "" },
		"empty ranges in record": func(b map[string]any) {
			b["vulnerabilities"].([]map[string]any)[0]["affected_ranges"] = []any{}
		},
		"bad fixed version in record": func(b map[string]any) {
			b["vulnerabilities"].([]map[string]any)[0]["fixed_version"] = "nope"
		},
		"bad severity in record": func(b map[string]any) {
			b["vulnerabilities"].([]map[string]any)[0]["severity"] = "urgent"
		},
		"bad status in record": func(b map[string]any) {
			b["vulnerabilities"].([]map[string]any)[0]["status"] = "closed"
		},
		"inverted range in record": func(b map[string]any) {
			b["vulnerabilities"].([]map[string]any)[0]["affected_ranges"] = []any{
				map[string]any{"lower": "3.0", "lower_include": true, "upper": "1.0", "upper_include": true},
			}
		},
		"missing include flag in record": func(b map[string]any) {
			b["vulnerabilities"].([]map[string]any)[0]["affected_ranges"] = []any{
				map[string]any{"lower": "2.0"},
			}
		},
		"wrong flag type in record": func(b map[string]any) {
			b["vulnerabilities"].([]map[string]any)[0]["affected_ranges"] = []any{
				map[string]any{"lower": "2.0", "lower_include": "yes"},
			}
		},
		"non-object element": func(b map[string]any) {
			b["vulnerabilities"] = []any{"CVE-2024-2000"}
		},
		"null element": func(b map[string]any) {
			b["vulnerabilities"] = []any{nil}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			router := newTestRouter(t)
			body := batchCreateBody("CVE-2024-2000")
			mutate(body)
			recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch", body)
			if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestBatchCreateRejectsMoreThan100(t *testing.T) {
	router := newTestRouter(t)
	entries := make([]map[string]any, 0, 101)
	for index := 0; index < 101; index++ {
		entries = append(entries, validCreateBody(
			"CVE-2024-"+string(rune('A'+index/26))+string(rune('A'+index%26))))
	}
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch",
		map[string]any{"vulnerabilities": entries})
	if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	list := doJSON(t, router, http.MethodGet, "/vulnerabilities", nil)
	var page struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &page); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if page.Total != 0 {
		t.Fatalf("oversized batch wrote %d records", page.Total)
	}
}

func TestBatchCreateExactly100Succeeds(t *testing.T) {
	router := newTestRouter(t)
	entries := make([]map[string]any, 0, 100)
	for index := 0; index < 100; index++ {
		id := "CVE-2024-" + string(rune('A'+index/26)) + string(rune('A'+index%26))
		entries = append(entries, validCreateBody(id))
	}
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch",
		map[string]any{"vulnerabilities": entries})
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if response.Count != 100 {
		t.Fatalf("count = %d, want 100", response.Count)
	}
}

func TestBatchCreateDuplicateWithinBatch(t *testing.T) {
	router := newTestRouter(t)
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch",
		batchCreateBody("CVE-2024-3001", "CVE-2024-3001"))
	if recorder.Code != http.StatusConflict || recorder.Body.String() != "error=DUPLICATE_VULNERABILITY" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	fetched := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-2024-3001", nil)
	if fetched.Code != http.StatusNotFound {
		t.Fatalf("duplicate batch must not insert: get status=%d", fetched.Code)
	}
}

func TestBatchCreateDuplicateAgainstStoredRecord(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-3002"))

	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch",
		batchCreateBody("CVE-2024-3003", "CVE-2024-3002"))
	if recorder.Code != http.StatusConflict || recorder.Body.String() != "error=DUPLICATE_VULNERABILITY" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	// The otherwise-new first record must not be partially committed.
	fetched := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-2024-3003", nil)
	if fetched.Code != http.StatusNotFound {
		t.Fatalf("batch left partial insert: get status=%d", fetched.Code)
	}
}

func TestBatchCreateValidatesBeforeDuplicateCheck(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-3004"))

	body := batchCreateBody("CVE-2024-3004", "CVE-2024-3005")
	body["vulnerabilities"].([]map[string]any)[1]["severity"] = "urgent"
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch", body)
	if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
		t.Fatalf("invalid record must take precedence: status=%d body=%q",
			recorder.Code, recorder.Body.String())
	}
}

func TestBatchCreateMalformedBody(t *testing.T) {
	router := newTestRouter(t)
	recorder := doRaw(t, router, "/vulnerabilities/batch", "{not json")
	if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestBatchCreateDoesNotDisturbSingleCreate(t *testing.T) {
	router := newTestRouter(t)
	registerVulnerability(t, router, validCreateBody("CVE-2024-4000"))

	// The single entry and batch entries share the same id space: a batch
	// duplicate against a single-created record must 409.
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch",
		batchCreateBody("CVE-2024-4000"))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", recorder.Code)
	}

	// A follow-up single create of a batch-unique id still works.
	recorder = doJSON(t, router, http.MethodPost, "/vulnerabilities",
		validCreateBody("CVE-2024-4001"))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("single create after batch status=%d body=%s",
			recorder.Code, recorder.Body.String())
	}
}
