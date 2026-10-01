package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/vuln-registry/internal/store"
	"github.com/luwa07832/vuln-registry/internal/version"
	"github.com/luwa07832/vuln-registry/internal/vuln"
)

const (
	bodyInvalidInput = "error=INVALID_INPUT"
	bodyDuplicate    = "error=DUPLICATE_VULNERABILITY"
	bodyNotFound     = "error=VULNERABILITY_NOT_FOUND"
)

// NewRouter wires the public HTTP surface.
func NewRouter(st *store.Store) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/healthz", func(c *gin.Context) {
		if err := st.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": gin.H{"code": "storage_unavailable", "message": "database is not available"}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "database": "ok"})
	})

	router.POST("/vulnerabilities", registerVulnerability(st))
	router.PATCH("/vulnerabilities/:id/status", updateVulnerabilityStatus(st))
	router.GET("/vulnerabilities/match", matchVulnerabilities(st))

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "route_not_found", "message": "no route matches this path"}})
	})
	return router
}

func registerVulnerability(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input vuln.RegisterInput
		if err := decodeJSONBody(c, &input); err != nil {
			writeInvalidInput(c)
			return
		}
		record, err := input.Validate()
		if err != nil {
			writeInvalidInput(c)
			return
		}
		if err := st.CreateVulnerability(record); err != nil {
			if errors.Is(err, store.ErrDuplicate) {
				writeTextError(c, http.StatusConflict, bodyDuplicate)
				return
			}
			writeInternalError(c)
			return
		}
		c.JSON(http.StatusCreated, record)
	}
}

func updateVulnerabilityStatus(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			writeInvalidInput(c)
			return
		}
		var body struct {
			Status *string `json:"status"`
		}
		if err := decodeJSONBody(c, &body); err != nil {
			writeInvalidInput(c)
			return
		}
		if body.Status == nil || !vuln.ValidStatus(*body.Status) {
			writeInvalidInput(c)
			return
		}
		record, err := st.SetVulnStatus(id, *body.Status)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeTextError(c, http.StatusNotFound, bodyNotFound)
				return
			}
			writeInternalError(c)
			return
		}
		c.JSON(http.StatusOK, record)
	}
}

func matchVulnerabilities(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		component := c.Query("component")
		versionText := c.Query("version")
		if component == "" {
			writeInvalidInput(c)
			return
		}
		target, err := version.Parse(versionText)
		if err != nil {
			writeInvalidInput(c)
			return
		}
		records, err := st.ListByComponent(component)
		if err != nil {
			writeInternalError(c)
			return
		}
		matches := make([]vuln.Match, 0)
		for _, record := range records {
			if hit := record.Match(target); hit != nil {
				matches = append(matches, *hit)
			}
		}
		c.JSON(http.StatusOK, matches)
	}
}

func decodeJSONBody(c *gin.Context, target any) error {
	if c.Request.Body == nil {
		return errors.New("empty body")
	}
	decoder := json.NewDecoder(c.Request.Body)
	return decoder.Decode(target)
}

func writeInvalidInput(c *gin.Context) {
	writeTextError(c, http.StatusBadRequest, bodyInvalidInput)
}

func writeTextError(c *gin.Context, status int, body string) {
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(status, body)
}

func writeInternalError(c *gin.Context) {
	c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "internal_error", "message": "request failed"}})
}
