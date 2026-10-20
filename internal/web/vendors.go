package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"netexplorer/internal/enrichment/macvendor"
)

// installVendors adds CSRF-protected registry actions; no target or URL is accepted.
func (h *scanHTTP) installVendors(router *gin.Engine) {
	router.GET("/api/vendors", func(c *gin.Context) { c.JSON(http.StatusOK, macvendor.Default.Status()) })
	router.POST("/api/vendors/update", func(c *gin.Context) {
		ctx := h.options.Context
		if ctx == nil {
			ctx = context.Background()
		}
		if err := macvendor.Default.Start(ctx); err != nil {
			slog.Warn("vendor registry update rejected", "error", err)
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusAccepted, macvendor.Default.Status())
	})
	router.POST("/api/vendors/settings", func(c *gin.Context) {
		var request struct {
			Automatic *bool `json:"automatic"`
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || request.Automatic == nil || decoder.Decode(new(any)) != io.EOF {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid registry settings"})
			return
		}
		if err := macvendor.Default.SetAutomatic(*request.Automatic); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to save registry settings"})
			return
		}
		c.JSON(http.StatusOK, macvendor.Default.Status())
	})
}
