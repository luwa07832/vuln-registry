package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/vuln-registry/internal/store"
	"github.com/luwa07832/vuln-registry/internal/vuln"
)

const (
	codeInvalidInput = "INVALID_INPUT"
	codeDuplicate    = "DUPLICATE_VULNERABILITY"
	codeNotFound     = "VULNERABILITY_NOT_FOUND"

	matchMaxComponents = 100
)

// rangeRequest is the affected-range payload of a registration.
type rangeRequest struct {
	Lower        *string `json:"lower"`
	LowerInclude *bool   `json:"lower_include"`
	Upper        *string `json:"upper"`
	UpperInclude *bool   `json:"upper_include"`
}

type createVulnerabilityRequest struct {
	ID           string         `json:"id"`
	Component    string         `json:"component"`
	Ranges       []rangeRequest `json:"affected_ranges"`
	Severity     string         `json:"severity"`
	FixedVersion string         `json:"fixed_version"`
	Status       string         `json:"status"`
}

type updateStatusRequest struct {
	Status string `json:"status"`
}

type matchComponentRequest struct {
	Component string `json:"component"`
	Version   string `json:"version"`
}

type matchVulnerabilitiesRequest struct {
	Components []matchComponentRequest `json:"components"`
}

// rangeMatchQuery is one finite version interval of a range-match request.
// The pointers distinguish a missing field from a present JSON value.
type rangeMatchQuery struct {
	Component    string `json:"component"`
	Lower        string `json:"lower"`
	Upper        string `json:"upper"`
	LowerInclude *bool  `json:"lower_include"`
	UpperInclude *bool  `json:"upper_include"`
}

type rangeMatchRequest struct {
	Queries []rangeMatchQuery `json:"queries"`
}

type matchComponentResult struct {
	Component       string                  `json:"component"`
	Version         string                  `json:"version"`
	Vulnerabilities []affectedVulnerability `json:"vulnerabilities"`
}

type matchVulnerabilitiesResponse struct {
	Results []matchComponentResult `json:"results"`
}

type rangeMatchResult struct {
	Component       string                  `json:"component"`
	Lower           string                  `json:"lower"`
	Upper           string                  `json:"upper"`
	LowerInclude    bool                    `json:"lower_include"`
	UpperInclude    bool                    `json:"upper_include"`
	Vulnerabilities []affectedVulnerability `json:"vulnerabilities"`
}

type rangeMatchResponse struct {
	Results []rangeMatchResult `json:"results"`
}

// listVulnerabilitiesResponse is the paginated list payload; items carries
// the full records of the requested page.
type listVulnerabilitiesResponse struct {
	Items    []*vuln.Vulnerability `json:"items"`
	Page     int                   `json:"page"`
	PageSize int                   `json:"page_size"`
	Total    int                   `json:"total"`
}

// affectedVulnerability is one element of the affected-query result; it carries
// only the requested projection of the full record.
type affectedVulnerability struct {
	ID            string        `json:"id"`
	Component     string        `json:"component"`
	MatchedRanges []vuln.Range  `json:"matched_ranges"`
	Severity      vuln.Severity `json:"severity"`
	FixedVersion  string        `json:"fixed_version"`
	Status        vuln.Status   `json:"status"`
}

func registerHandlers(router *gin.Engine, st *store.Store) {
	router.POST("/vulnerabilities", func(c *gin.Context) {
		createVulnerability(c, st)
	})
	router.GET("/vulnerabilities", func(c *gin.Context) {
		listVulnerabilities(c, st)
	})
	router.GET("/vulnerabilities/affected", func(c *gin.Context) {
		queryAffected(c, st)
	})
	router.POST("/vulnerabilities/match", func(c *gin.Context) {
		matchVulnerabilities(c, st)
	})
	router.POST("/vulnerabilities/range-match", func(c *gin.Context) {
		matchRanges(c, st)
	})
	router.GET("/vulnerabilities/:id", func(c *gin.Context) {
		getVulnerability(c, st)
	})
	router.PATCH("/vulnerabilities/status/:id", func(c *gin.Context) {
		updateStatus(c, st)
	})
}

func getVulnerability(c *gin.Context, st *store.Store) {
	record, err := st.GetVulnerability(c.Request.Context(), c.Param("id"))
	if err != nil {
		if errors.Is(err, store.ErrVulnerabilityNotFound) {
			respondFixed(c, http.StatusNotFound, codeNotFound)
			return
		}
		respondStorageError(c)
		return
	}
	c.JSON(http.StatusOK, record)
}

func createVulnerability(c *gin.Context, st *store.Store) {
	var request createVulnerabilityRequest
	if err := decodeBody(c, &request); err != nil {
		respondInvalidInput(c)
		return
	}

	if request.ID == "" || request.Component == "" || request.FixedVersion == "" {
		respondInvalidInput(c)
		return
	}
	if _, err := vuln.ParseVersion(request.FixedVersion); err != nil {
		respondInvalidInput(c)
		return
	}
	severity := vuln.Severity(request.Severity)
	status := vuln.Status(request.Status)
	if !vuln.ValidSeverity(severity) || !vuln.ValidStatus(status) || len(request.Ranges) == 0 {
		respondInvalidInput(c)
		return
	}

	record := &vuln.Vulnerability{
		ID:           request.ID,
		Component:    request.Component,
		Ranges:       make([]vuln.Range, 0, len(request.Ranges)),
		Severity:     severity,
		FixedVersion: request.FixedVersion,
		Status:       status,
	}
	for _, affected := range request.Ranges {
		record.Ranges = append(record.Ranges, vuln.Range{
			Lower:        normalizeBound(affected.Lower),
			LowerInclude: affected.LowerInclude,
			Upper:        normalizeBound(affected.Upper),
			UpperInclude: affected.UpperInclude,
		})
	}
	if err := record.PrepareRanges(); err != nil {
		respondInvalidInput(c)
		return
	}

	if err := st.CreateVulnerability(c.Request.Context(), record); err != nil {
		if errors.Is(err, store.ErrDuplicateVulnerability) {
			respondFixed(c, http.StatusConflict, codeDuplicate)
			return
		}
		respondStorageError(c)
		return
	}
	c.JSON(http.StatusCreated, record)
}

func queryAffected(c *gin.Context, st *store.Store) {
	component := c.Query("component")
	versionText := c.Query("version")
	if component == "" {
		respondInvalidInput(c)
		return
	}
	version, err := vuln.ParseVersion(versionText)
	if err != nil {
		respondInvalidInput(c)
		return
	}

	records, err := st.ListByComponent(c.Request.Context(), component)
	if err != nil {
		respondStorageError(c)
		return
	}

	results := []affectedVulnerability{}
	for _, record := range records {
		matched := record.MatchedRanges(version)
		if len(matched) == 0 {
			continue
		}
		results = append(results, affectedVulnerability{
			ID:            record.ID,
			Component:     record.Component,
			MatchedRanges: matched,
			Severity:      record.Severity,
			FixedVersion:  record.FixedVersion,
			Status:        record.Status,
		})
	}
	c.JSON(http.StatusOK, results)
}

// matchVulnerabilities evaluates a batch of component versions against the
// registered affected ranges. Results mirror the input order; duplicates are
// handled independently and entries without hits carry an empty array.
func matchVulnerabilities(c *gin.Context, st *store.Store) {
	var request matchVulnerabilitiesRequest
	if err := decodeBody(c, &request); err != nil {
		respondInvalidInput(c)
		return
	}
	if len(request.Components) == 0 || len(request.Components) > matchMaxComponents {
		respondInvalidInput(c)
		return
	}
	parsedVersions := make([]vuln.Version, len(request.Components))
	for index, item := range request.Components {
		if item.Component == "" {
			respondInvalidInput(c)
			return
		}
		parsed, err := vuln.ParseVersion(item.Version)
		if err != nil {
			respondInvalidInput(c)
			return
		}
		parsedVersions[index] = parsed
	}

	results := make([]matchComponentResult, len(request.Components))
	for index, item := range request.Components {
		records, err := st.ListByComponent(c.Request.Context(), item.Component)
		if err != nil {
			respondStorageError(c)
			return
		}
		hits := []affectedVulnerability{}
		for _, record := range records {
			matched := record.MatchedRanges(parsedVersions[index])
			if len(matched) == 0 {
				continue
			}
			hits = append(hits, affectedVulnerability{
				ID:            record.ID,
				Component:     record.Component,
				MatchedRanges: matched,
				Severity:      record.Severity,
				FixedVersion:  record.FixedVersion,
				Status:        record.Status,
			})
		}
		results[index] = matchComponentResult{
			Component:       item.Component,
			Version:         item.Version,
			Vulnerabilities: hits,
		}
	}
	c.JSON(http.StatusOK, matchVulnerabilitiesResponse{Results: results})
}

// matchRanges evaluates a batch of finite version intervals against the
// registered affected ranges. Results mirror the input order; every status
// participates and entries without hits carry an empty array.
func matchRanges(c *gin.Context, st *store.Store) {
	var request rangeMatchRequest
	if err := decodeBody(c, &request); err != nil {
		respondInvalidInput(c)
		return
	}
	if len(request.Queries) == 0 || len(request.Queries) > matchMaxComponents {
		respondInvalidInput(c)
		return
	}
	intervals := make([]vuln.IntervalQuery, len(request.Queries))
	for index, item := range request.Queries {
		if item.Component == "" || item.LowerInclude == nil || item.UpperInclude == nil {
			respondInvalidInput(c)
			return
		}
		interval, err := vuln.NewIntervalQuery(item.Lower, item.Upper, *item.LowerInclude, *item.UpperInclude)
		if err != nil {
			respondInvalidInput(c)
			return
		}
		intervals[index] = interval
	}

	results := make([]rangeMatchResult, len(request.Queries))
	for index, item := range request.Queries {
		records, err := st.ListByComponent(c.Request.Context(), item.Component)
		if err != nil {
			respondStorageError(c)
			return
		}
		hits := []affectedVulnerability{}
		for _, record := range records {
			matched := record.MatchedRangesInInterval(intervals[index])
			if len(matched) == 0 {
				continue
			}
			hits = append(hits, affectedVulnerability{
				ID:            record.ID,
				Component:     record.Component,
				MatchedRanges: matched,
				Severity:      record.Severity,
				FixedVersion:  record.FixedVersion,
				Status:        record.Status,
			})
		}
		results[index] = rangeMatchResult{
			Component:       item.Component,
			Lower:           item.Lower,
			Upper:           item.Upper,
			LowerInclude:    *item.LowerInclude,
			UpperInclude:    *item.UpperInclude,
			Vulnerabilities: hits,
		}
	}
	c.JSON(http.StatusOK, rangeMatchResponse{Results: results})
}

func updateStatus(c *gin.Context, st *store.Store) {
	var request updateStatusRequest
	if err := decodeBody(c, &request); err != nil {
		respondInvalidInput(c)
		return
	}
	status := vuln.Status(request.Status)
	if !vuln.ValidStatus(status) {
		respondInvalidInput(c)
		return
	}

	record, err := st.UpdateStatus(c.Request.Context(), c.Param("id"), status)
	if err != nil {
		if errors.Is(err, store.ErrVulnerabilityNotFound) {
			respondFixed(c, http.StatusNotFound, codeNotFound)
			return
		}
		respondStorageError(c)
		return
	}
	c.JSON(http.StatusOK, record)
}

// listVulnerabilities serves the paginated list entry. The component,
// severity and status filters intersect; any other query parameter is
// ignored rather than rejected.
func listVulnerabilities(c *gin.Context, st *store.Store) {
	filter := store.ListFilter{}
	if component, present := c.GetQuery("component"); present {
		if component == "" {
			respondInvalidInput(c)
			return
		}
		filter.Component = &component
	}
	if severity, present := c.GetQuery("severity"); present {
		parsed := vuln.Severity(severity)
		if !vuln.ValidSeverity(parsed) {
			respondInvalidInput(c)
			return
		}
		filter.Severity = &parsed
	}
	if status, present := c.GetQuery("status"); present {
		parsed := vuln.Status(status)
		if !vuln.ValidStatus(parsed) {
			respondInvalidInput(c)
			return
		}
		filter.Status = &parsed
	}

	page := 1
	if raw, present := c.GetQuery("page"); present {
		parsed, ok := parsePositiveDecimal(raw)
		if !ok {
			respondInvalidInput(c)
			return
		}
		page = parsed
	}
	pageSize := 20
	if raw, present := c.GetQuery("page_size"); present {
		parsed, ok := parsePositiveDecimal(raw)
		if !ok || parsed > 100 {
			respondInvalidInput(c)
			return
		}
		pageSize = parsed
	}

	records, total, err := st.ListVulnerabilities(c.Request.Context(), filter, page, pageSize)
	if err != nil {
		respondStorageError(c)
		return
	}
	c.JSON(http.StatusOK, listVulnerabilitiesResponse{
		Items:    records,
		Page:     page,
		PageSize: pageSize,
		Total:    total,
	})
}

// parsePositiveDecimal accepts only strings of decimal digits that form a
// positive integer, rejecting signs, whitespace, fractions and overflow.
func parsePositiveDecimal(raw string) (int, bool) {
	if raw == "" {
		return 0, false
	}
	for _, digit := range raw {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0, false
	}
	return value, true
}

func decodeBody(c *gin.Context, target any) error {
	decoder := json.NewDecoder(c.Request.Body)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); errors.Is(err, io.EOF) {
		return nil
	} else if err == nil {
		return errors.New("body must contain a single JSON object")
	} else {
		return err
	}
}

func normalizeBound(bound *string) *string {
	if bound == nil || *bound == "" {
		return nil
	}
	return bound
}

// respondFixed emits the fixed error body mandated for the new entries, e.g.
// "error=DUPLICATE_VULNERABILITY".
func respondFixed(c *gin.Context, status int, code string) {
	c.Data(status, "text/plain; charset=utf-8", []byte("error="+code))
}

func respondInvalidInput(c *gin.Context) {
	respondFixed(c, http.StatusBadRequest, codeInvalidInput)
}

func respondStorageError(c *gin.Context) {
	c.JSON(http.StatusInternalServerError, gin.H{
		"error": gin.H{"code": "internal_error", "message": "request could not be completed"},
	})
}
