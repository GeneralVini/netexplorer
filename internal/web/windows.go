package web

import (
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/windows"
	"netexplorer/internal/scanner"
	"time"
)

// installWindows exposes the fixed collector, local import and manual remote collection.
func (h *scanHTTP) installWindows(router *gin.Engine) {
	router.GET("/api/windows/collector", func(c *gin.Context) {
		c.Header("Content-Disposition", `attachment; filename="collect-windows.ps1"`)
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(windows.Collector))
	})
	router.GET("/api/hosts/:id/windows", func(c *gin.Context) {
		for _, host := range h.hosts() {
			if host.ID == c.Param("id") {
				sshReady := false
				for _, port := range host.Ports {
					if port.Number == 22 && port.Protocol == "tcp" && port.State == "open" && (port.Service == "ssh" || port.Service == "ssh?" || port.Service == "unknown" || port.Service == "") {
						sshReady = true
					}
				}
				report, ok := h.options.Manager.WindowsReport(host.ID)
				if !ok {
					c.JSON(http.StatusOK, gin.H{"report": nil, "ssh_ready": sshReady})
					return
				}
				c.JSON(http.StatusOK, gin.H{"report": report, "ssh_ready": sshReady})
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
	})
	router.POST("/api/hosts/:id/windows", h.importWindows)
	router.POST("/api/hosts/:id/windows/ssh", h.collectWindowsSSH)
}

// importWindows never opens a client-supplied path or starts a subprocess.
func (h *scanHTTP) importWindows(c *gin.Context) {
	latest, ok := h.options.Manager.Latest()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "no inventory available"})
		return
	}
	ip := ""
	for _, host := range latest.Report.Hosts {
		if host.ID == c.Param("id") {
			ip = host.IP
		}
	}
	if ip == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 262144)
	snapshot, err := windows.Decode(c.Request.Body, ip, time.Now())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	report, err := h.options.Manager.ImportWindows(latest.ID, c.Param("id"), snapshot)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"report": report})
}

// collectWindowsSSH accepts an authorized username selector, never passwords or commands.
func (h *scanHTTP) collectWindowsSSH(c *gin.Context) {
	var request struct {
		Authorized bool   `json:"authorized"`
		User       string `json:"user"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !request.Authorized {
		c.JSON(http.StatusBadRequest, gin.H{"error": "explicit authorization and a valid username are required"})
		return
	}
	latest, ok := h.options.Manager.Latest()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "no inventory available"})
		return
	}
	items, err := h.interfaces()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to enumerate interfaces"})
		return
	}
	selected, err := network.Select(items, latest.Interface, latest.Interface)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan interface unavailable"})
		return
	}
	report, err := h.options.Manager.CollectWindowsSSH(c.Request.Context(), selected, c.Param("id"), request.User)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, scanner.ErrBusy) {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"report": report})
}
