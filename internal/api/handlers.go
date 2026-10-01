package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/vuln-registry/internal/store"
	"github.com/luwa07832/vuln-registry/internal/vuln"
)

const (
	codeInvalidInput = "INVALID_INPUT"
	codeDuplicate    = "DUPLICATE_VULNERABILITY"
	codeNotFound     = "VULNERABILITY_NOT_FOUND"
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
	router.GET("/vulnerabilities/affected", func(c *gin.Context) {
		queryAffected(c, st)
	})
	router.GET("/vulnerabilities/:id", func(c *gin.Context) {
		getVulnerability(c, st)
	})
	router.PATCH("/vulnerabilities/status/:id", func(c *gin.Context) {
		updateStatus(c, st)
	})
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

// getVulnerability returns the full record registered under the exact id in
// the path. The lookup is read-only and never folds case or trims the id.
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
