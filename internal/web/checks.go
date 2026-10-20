package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/nmap"
	"netexplorer/internal/scanner"
)

// installChecks exposes catalog, inventory-scoped manual actions and retained results.
func (h *scanHTTP) installChecks(router *gin.Engine) {
	h.installWindows(router)
	router.GET("/api/checks/catalog", func(c *gin.Context) { c.JSON(http.StatusOK, nmap.CheckCatalog()) })
	router.POST("/api/hosts/:id/checks", h.startCheck)
	router.GET("/api/hosts/:id/checks", func(c *gin.Context) {
		for _, host := range h.hosts() {
			if host.ID == c.Param("id") {
				c.JSON(http.StatusOK, h.options.Manager.CheckJobs(host.ID))
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
	})
	router.GET("/api/checks/:id", func(c *gin.Context) {
		job, ok := h.options.Manager.CheckState(c.Param("id"))
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "check job not found"})
			return
		}
		c.JSON(http.StatusOK, job)
	})
	router.POST("/api/checks/:id/cancel", func(c *gin.Context) {
		if !h.options.Manager.CancelCheck(c.Param("id")) {
			c.JSON(http.StatusNotFound, gin.H{"error": "check job not found"})
			return
		}
		c.Status(http.StatusAccepted)
	})
}

// startCheck accepts only an authorized catalog selector and an existing observed port.
func (h *scanHTTP) startCheck(c *gin.Context) {
	var request struct {
		Authorized bool   `json:"authorized"`
		CheckID    string `json:"check_id"`
		Port       int    `json:"port"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid check request"})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF || !request.Authorized {
		c.JSON(http.StatusBadRequest, gin.H{"error": "explicit LAN authorization is required"})
		return
	}
	if _, err := nmap.CheckSpecFor(request.CheckID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	latest, ok := h.options.Manager.Latest()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "no inventory available"})
		return
	}
	exists := false
	for _, host := range latest.Report.Hosts {
		if host.ID == c.Param("id") {
			exists = true
		}
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}
	items, err := h.interfaces()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to enumerate interfaces"})
		return
	}
	selected, err := network.Select(items, latest.Interface, latest.Interface)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan interface is unavailable"})
		return
	}
	job, err := h.options.Manager.StartCheck(c.Param("id"), selected, request.CheckID, request.Port)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, scanner.ErrBusy) {
			status = http.StatusConflict
		}
		if errors.Is(err, nmap.ErrUnavailable) {
			status = http.StatusServiceUnavailable
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.Header("Location", "/api/checks/"+job.ID)
	c.JSON(http.StatusAccepted, job)
}
