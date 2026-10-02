package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func doRawJSON(t *testing.T, router http.Handler, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, target, bytes.NewReader([]byte(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func batchBody(ids ...string) map[string]any {
	items := make([]any, 0, len(ids))
	for index, id := range ids {
		item := validCreateBody(id)
		if id == "" {
			item["id"] = ""
		}
		item["component"] = fmt.Sprintf("comp-%d", index)
		items = append(items, item)
	}
	return map[string]any{"vulnerabilities": items}
}

func TestCreateBatchSuccess(t *testing.T) {
	router := newTestRouter(t)
	body := batchBody("CVE-2024-0001", "CVE-2024-0002")
	body["ignored"] = true
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch", body)

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
	if response.Count != 2 || len(response.Items) != 2 {
		t.Fatalf("count/items wrong: count=%d items=%d", response.Count, len(response.Items))
	}
	if response.Items[0].ID != "CVE-2024-0001" || response.Items[1].ID != "CVE-2024-0002" {
		t.Fatalf("items must mirror input order: %#v", response.Items)
	}
	if response.Items[1].Component != "comp-1" {
		t.Fatalf("component wrong: %q", response.Items[1].Component)
	}
	if len(response.Items[0].Ranges) != 2 || response.Items[0].Ranges[1].Lower != nil {
		t.Fatalf("ranges wrong: %#v", response.Items[0].Ranges)
	}

	for _, id := range []string{"CVE-2024-0001", "CVE-2024-0002"} {
		got := doJSON(t, router, http.MethodGet, "/vulnerabilities/"+id, nil)
		if got.Code != http.StatusOK {
			t.Fatalf("get %s status = %d", id, got.Code)
		}
	}
}

func TestCreateBatchSingleStillReachable(t *testing.T) {
	router := newTestRouter(t)
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities", validCreateBody("CVE-2024-0003"))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("single create status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCreateBatchInvalidInputs(t *testing.T) {
	cases := map[string]string{
		"not an object":             `[1,2]`,
		"missing vulnerabilities":   `{}`,
		"vulnerabilities null":      `{"vulnerabilities":null}`,
		"empty array":               `{"vulnerabilities":[]}`,
		"element not object":        `{"vulnerabilities":[42]}`,
		"element missing id":        `{"vulnerabilities":[{"component":"c","affected_ranges":[{"lower":"1.0","lower_include":true}],"severity":"low","fixed_version":"2.0","status":"open"}]}`,
		"element empty id":          `{"vulnerabilities":[{"id":"","component":"c","affected_ranges":[{"lower":"1.0","lower_include":true}],"severity":"low","fixed_version":"2.0","status":"open"}]}`,
		"element empty component":   `{"vulnerabilities":[{"id":"X","component":"","affected_ranges":[{"lower":"1.0","lower_include":true}],"severity":"low","fixed_version":"2.0","status":"open"}]}`,
		"element missing ranges":    `{"vulnerabilities":[{"id":"X","component":"c","severity":"low","fixed_version":"2.0","status":"open"}]}`,
		"element empty ranges":      `{"vulnerabilities":[{"id":"X","component":"c","affected_ranges":[],"severity":"low","fixed_version":"2.0","status":"open"}]}`,
		"element bad fixed version": `{"vulnerabilities":[{"id":"X","component":"c","affected_ranges":[{"lower":"1.0","lower_include":true}],"severity":"low","fixed_version":"2.x","status":"open"}]}`,
		"element bad severity":      `{"vulnerabilities":[{"id":"X","component":"c","affected_ranges":[{"lower":"1.0","lower_include":true}],"severity":"urgent","fixed_version":"2.0","status":"open"}]}`,
		"element bad status":        `{"vulnerabilities":[{"id":"X","component":"c","affected_ranges":[{"lower":"1.0","lower_include":true}],"severity":"low","fixed_version":"2.0","status":"done"}]}`,
		"element inverted range":    `{"vulnerabilities":[{"id":"X","component":"c","affected_ranges":[{"lower":"2.0","lower_include":true,"upper":"1.0","upper_include":true}],"severity":"low","fixed_version":"2.0","status":"open"}]}`,
		"element missing include":   `{"vulnerabilities":[{"id":"X","component":"c","affected_ranges":[{"lower":"1.0"}],"severity":"low","fixed_version":"2.0","status":"open"}]}`,
		"element include not bool":  `{"vulnerabilities":[{"id":"X","component":"c","affected_ranges":[{"lower":"1.0","lower_include":"yes"}],"severity":"low","fixed_version":"2.0","status":"open"}]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			router := newTestRouter(t)
			recorder := doRawJSON(t, router, "/vulnerabilities/batch", raw)
			if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestCreateBatchIgnoresUnknownFields(t *testing.T) {
	router := newTestRouter(t)
	raw := `{"vulnerabilities":[{"id":"X","component":"c","affected_ranges":[{"lower":"1.0","lower_include":true,"note":"x"}],"severity":"low","fixed_version":"2.0","status":"open","extra":1}],"meta":true}`
	recorder := doRawJSON(t, router, "/vulnerabilities/batch", raw)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestCreateBatchRejectsOver100Items(t *testing.T) {
	router := newTestRouter(t)
	ids := make([]string, 0, 101)
	for index := 0; index < 101; index++ {
		ids = append(ids, fmt.Sprintf("CVE-2024-%05d", index))
	}
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch", batchBody(ids...))
	if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestCreateBatchAcceptsExactly100Items(t *testing.T) {
	router := newTestRouter(t)
	ids := make([]string, 0, 100)
	for index := 0; index < 100; index++ {
		ids = append(ids, fmt.Sprintf("CVE-2025-%05d", index))
	}
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch", batchBody(ids...))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCreateBatchDuplicateWithinBatch(t *testing.T) {
	router := newTestRouter(t)
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch", batchBody("CVE-X1", "CVE-X1"))
	if recorder.Code != http.StatusConflict || recorder.Body.String() != "error=DUPLICATE_VULNERABILITY" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	got := doJSON(t, router, http.MethodGet, "/vulnerabilities/CVE-X1", nil)
	if got.Code != http.StatusNotFound {
		t.Fatalf("duplicate batch must not insert, get status = %d", got.Code)
	}
}

func TestCreateBatchDuplicateAgainstStore(t *testing.T) {
	router := newTestRouter(t)
	first := doJSON(t, router, http.MethodPost, "/vulnerabilities", validCreateBody("CVE-EXISTING"))
	if first.Code != http.StatusCreated {
		t.Fatalf("seed status = %d", first.Code)
	}
	recorder := doJSON(t, router, http.MethodPost, "/vulnerabilities/batch", batchBody("CVE-NEW", "CVE-EXISTING", "CVE-NEW2"))
	if recorder.Code != http.StatusConflict || recorder.Body.String() != "error=DUPLICATE_VULNERABILITY" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	for _, id := range []string{"CVE-NEW", "CVE-NEW2"} {
		if got := doJSON(t, router, http.MethodGet, "/vulnerabilities/"+id, nil); got.Code != http.StatusNotFound {
			t.Fatalf("%s must not be partially committed, get status = %d", id, got.Code)
		}
	}
}

func TestCreateBatchValidationBeforeDuplicateCheck(t *testing.T) {
	router := newTestRouter(t)
	if first := doJSON(t, router, http.MethodPost, "/vulnerabilities", validCreateBody("CVE-SEED")); first.Code != http.StatusCreated {
		t.Fatalf("seed status = %d", first.Code)
	}
	raw := `{"vulnerabilities":[{"id":"CVE-SEED","component":"c","affected_ranges":[{"lower":"1.0","lower_include":true}],"severity":"low","fixed_version":"2.0","status":"open"},{"id":"CVE-DUP","component":"c","affected_ranges":[],"severity":"low","fixed_version":"2.0","status":"open"}]}`
	recorder := doRawJSON(t, router, "/vulnerabilities/batch", raw)
	if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "error=INVALID_INPUT" {
		t.Fatalf("invalid record must win over duplicate, status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}
