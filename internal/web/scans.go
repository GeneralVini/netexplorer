package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/nmap"
	"netexplorer/internal/inventory"
	"netexplorer/internal/scanner"
	"netexplorer/internal/tools"
)

// assets contains pinned local dependencies and the browser controller.
//
//go:embed assets/*
var assets embed.FS

// Options connects the HTTP layer to an application-owned scan manager.
type Options struct {
	// Context cancels application-owned background tasks.
	Context context.Context
	// Manager owns scan workers and must be closed by the caller.
	Manager *scanner.Manager
	// DefaultInterface is selected when a request omits its interface.
	DefaultInterface string
	// Listen is the configured listener used to validate Host headers.
	Listen string
}

// scanHTTP holds startup secrets and a bounded SSE connection semaphore.
type scanHTTP struct {
	archiveMu  sync.RWMutex
	archive    *snapshot
	options    Options
	interfaces func() ([]network.Interface, error)
	token      string
	streams    chan struct{}
	host       string
	port       string
}

// newScanHTTP generates a process-local CSRF token and listener policy.
func newScanHTTP(options Options, interfaces func() ([]network.Interface, error)) *scanHTTP {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("unable to initialize HTTP CSRF protection")
	}
	host, port, err := net.SplitHostPort(options.Listen)
	if err != nil {
		host = "127.0.0.1"
		port = "8080"
	}
	return &scanHTTP{options: options, interfaces: interfaces, token: hex.EncodeToString(secret), streams: make(chan struct{}, 16), host: host, port: port}
}

// protect rejects unexpected hosts and cross-origin writes before handler execution.
func (h *scanHTTP) protect(c *gin.Context) {
	host, port, err := net.SplitHostPort(c.Request.Host)
	if err != nil {
		host = c.Request.Host
		port = "80"
	}
	allowed := host == h.host
	ip := net.ParseIP(host)
	bound := net.ParseIP(h.host)
	if bound != nil && bound.IsLoopback() {
		allowed = host == "localhost" || (ip != nil && ip.IsLoopback())
	}
	if h.host == "0.0.0.0" || h.host == "::" {
		allowed = ip != nil
	}
	if !allowed || port != h.port {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "unexpected HTTP host"})
		return
	}
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	c.Header("Cache-Control", "no-store")
	if c.Request.Method == http.MethodPost {
		if err := http.NewCrossOriginProtection().Check(c.Request); err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "cross-origin request rejected"})
			return
		}
		token := c.GetHeader("X-CSRF-Token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(h.token)) != 1 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid CSRF token"})
			return
		}
	}
	if c.Request.Method == http.MethodPost && h.offline() && c.Request.URL.Path != "/api/snapshots/load" && c.Request.URL.Path != "/api/snapshots/live" {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "saved inventory is read-only; return to Live inventory before running actions"})
		return
	}
	c.Next()
}

// install registers inventory, scan lifecycle, and local asset routes.
func (h *scanHTTP) install(router *gin.Engine) {
	public := publicAssets()
	router.GET("/static/*filepath", func(c *gin.Context) {
		name := strings.TrimPrefix(c.Param("filepath"), "/")
		contentType, allowed := public[name]
		if !allowed {
			c.Status(http.StatusNotFound)
			return
		}
		data, err := assets.ReadFile("assets/" + name)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Data(http.StatusOK, contentType, data)
	})
	router.GET("/api/devices", func(c *gin.Context) { c.JSON(http.StatusOK, h.devices()) })
	router.GET("/api/devices/:id", func(c *gin.Context) {
		for _, d := range h.devices() {
			if d.ID == c.Param("id") {
				c.JSON(http.StatusOK, d)
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
	})
	router.GET("/devices", func(c *gin.Context) {
		data := gin.H{"Devices": []inventory.Device{}, "Hosts": []inventory.Host{}, "NmapAvailable": h.options.Manager.NmapAvailable() && !h.offline(), "Offline": h.offline()}
		if state, ok := h.current(); ok {
			data["Devices"] = state.Report.Devices
			data["Hosts"] = state.Report.Hosts
		}
		c.HTML(http.StatusOK, "devices", data)
	})
	h.installChecks(router)
	router.GET("/api/tools", func(c *gin.Context) {
		c.JSON(http.StatusOK, tools.Discover("nmap", "arp-scan", "smbclient", "showmount", "ssh", "pwsh"))
	})
	router.GET("/api/hosts", func(c *gin.Context) { c.JSON(http.StatusOK, h.hosts()) })
	router.GET("/api/hosts/:id", func(c *gin.Context) {
		for _, host := range h.hosts() {
			if host.ID == c.Param("id") {
				c.JSON(http.StatusOK, host)
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
	})
	router.POST("/api/devices/:id/nmap", h.startNmap)
	router.POST("/api/hosts/:id/nmap", h.startNmap)
	router.GET("/api/hosts/:id/services", h.serviceDetails)
	router.POST("/api/hosts/:id/shares", h.listShares)
	router.GET("/api/nmap/:id", func(c *gin.Context) {
		job, ok := h.options.Manager.NmapState(c.Param("id"))
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "Nmap job not found"})
			return
		}
		c.JSON(http.StatusOK, job)
	})
	router.POST("/api/nmap/:id/cancel", func(c *gin.Context) {
		if !h.options.Manager.CancelNmap(c.Param("id")) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Nmap job not found"})
			return
		}
		c.Status(http.StatusAccepted)
	})
	router.POST("/api/scans", h.start)
	router.GET("/api/scans/latest", func(c *gin.Context) {
		state, ok := h.current()
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "no scans yet"})
			return
		}
		c.JSON(http.StatusOK, state)
	})
	router.GET("/api/scans/:id", func(c *gin.Context) {
		state, ok := h.options.Manager.State(c.Param("id"))
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}
		c.JSON(http.StatusOK, state)
	})
	router.POST("/api/scans/:id/cancel", func(c *gin.Context) {
		if !h.options.Manager.Cancel(c.Param("id")) {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}
		c.Status(http.StatusAccepted)
	})
	for _, action := range []string{"pause", "resume"} {
		paused := action == "pause"
		router.POST("/api/scans/:id/"+action, func(c *gin.Context) {
			if !h.options.Manager.SetPaused(c.Param("id"), paused) {
				c.JSON(http.StatusConflict, gin.H{"error": "Only running continuous discovery can be paused or resumed"})
				return
			}
			c.Status(http.StatusAccepted)
		})
	}
	router.GET("/api/scans/:id/events", h.events)
}

// devices exposes only the latest scan and returns an empty JSON array initially.
func (h *scanHTTP) devices() []inventory.Device {
	state, ok := h.current()
	if !ok || state.Report.Devices == nil {
		return []inventory.Device{}
	}
	return state.Report.Devices
}

// start accepts a small, strict JSON request; no discovery happens on GET routes.
func (h *scanHTTP) start(c *gin.Context) {
	var request struct {
		Interface       string `json:"interface"`
		Seconds         int    `json:"seconds"`
		Enrich          bool   `json:"enrich"`
		Authorized      bool   `json:"authorized"`
		AllHosts        bool   `json:"all_hosts"`
		Continuous      bool   `json:"continuous"`
		IntervalSeconds int    `json:"interval_seconds"`
		AutoTCP         bool   `json:"auto_tcp"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan request"})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expected a single JSON object"})
		return
	}
	if !request.Authorized {
		c.JSON(http.StatusBadRequest, gin.H{"error": "LAN authorization is required"})
		return
	}
	if request.Seconds == 0 {
		request.Seconds = 5
	}
	if request.Seconds < 1 || request.Seconds > 60 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "seconds must be between 1 and 60"})
		return
	}
	items, err := h.interfaces()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to enumerate interfaces"})
		return
	}
	name := request.Interface
	if name == "" {
		name = h.options.DefaultInterface
	}
	selected, err := network.Select(items, name, h.options.DefaultInterface)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "interface is unavailable"})
		return
	}
	if request.Continuous && request.IntervalSeconds == 0 {
		request.IntervalSeconds = 30
	}
	if request.IntervalSeconds != 0 && (request.IntervalSeconds < 10 || request.IntervalSeconds > 3600) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "interval_seconds must be between 10 and 3600"})
		return
	}
	id, err := h.options.Manager.StartWithOptions(selected, time.Duration(request.Seconds)*time.Second, scanner.ScanOptions{Enrich: request.Enrich, AllHosts: request.AllHosts, Continuous: request.Continuous, Interval: time.Duration(request.IntervalSeconds) * time.Second, AutoTCP: request.AutoTCP})
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
	c.Header("Location", "/api/scans/"+id)
	c.JSON(http.StatusAccepted, gin.H{"id": id, "events": "/api/scans/" + id + "/events"})
}

// events streams bounded replay batches and heartbeats with per-write deadlines.
// Slow readers never block scan workers; terminal scans close the connection.
func (h *scanHTTP) events(c *gin.Context) {
	cursor := uint64(0)
	if raw := c.GetHeader("Last-Event-ID"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Last-Event-ID"})
			return
		}
		cursor = parsed
	}
	id := c.Param("id")
	if _, _, _, _, ok := h.options.Manager.Events(id, cursor); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	select {
	case h.streams <- struct{}{}:
		defer func() { <-h.streams }()
	default:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "event stream limit reached"})
		return
	}
	c.Header("Content-Type", "text/event-stream")
	c.Header("X-Accel-Buffering", "no")
	control := http.NewResponseController(c.Writer)
	write := func(message string) bool {
		if err := control.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return false
		}
		if _, err := io.WriteString(c.Writer, message); err != nil {
			return false
		}
		return control.Flush() == nil
	}
	heartbeat := time.NewTicker(10 * time.Second)
	defer heartbeat.Stop()
	lifetime := time.NewTimer(2 * time.Minute)
	defer lifetime.Stop()
	if !write(": connected\n\n") {
		return
	}
	for {
		events, notify, done, reset, ok := h.options.Manager.Events(id, cursor)
		if !ok {
			return
		}
		if reset {
			if !write("event: reset\ndata: {}\n\n") {
				return
			}
		}
		for _, event := range events {
			if !write(fmt.Sprintf("id: %d\nevent: %s\ndata: %s\n\n", event.ID, event.Type, event.Data)) {
				return
			}
			cursor = event.ID
		}
		if done {
			return
		}
		select {
		case <-c.Request.Context().Done():
			return
		case <-lifetime.C:
			return
		case <-notify:
		case <-heartbeat.C:
			if !write(": heartbeat\n\n") {
				return
			}
		}
	}
}

// publicAssets explicitly permits only application assets, never licenses or metadata.
func publicAssets() map[string]string {
	result := map[string]string{
		"bootstrap.min.css": "text/css; charset=utf-8",
		"app.css":           "text/css; charset=utf-8",
		"htmx.min.js":       "text/javascript; charset=utf-8",
		"app.js":            "text/javascript; charset=utf-8",
		"favicon.svg":       "image/svg+xml",
		"icons/devices.svg": "image/svg+xml",
	}
	for _, brand := range vendors {
		result["icons/vendor-"+brand.slug+".svg"] = "image/svg+xml"
	}
	return result
}

// hosts returns detached IP evidence from the latest scan, including SSDP hosts.
func (h *scanHTTP) hosts() []inventory.Host {
	state, ok := h.current()
	if !ok || state.Report.Hosts == nil {
		return []inventory.Host{}
	}
	return state.Report.Hosts
}

// startNmap validates a small authorization body and an existing inventory target.
func (h *scanHTTP) startNmap(c *gin.Context) {
	var request struct {
		Authorized bool   `json:"authorized"`
		Profile    string `json:"profile"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Nmap request"})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF || !request.Authorized {
		c.JSON(http.StatusBadRequest, gin.H{"error": "explicit LAN authorization is required"})
		return
	}
	if !h.options.Manager.NmapAvailable() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Nmap is unavailable on PATH"})
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
	for _, device := range latest.Report.Devices {
		if device.ID == c.Param("id") {
			exists = true
		}
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "target not found in latest inventory"})
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
	job, err := h.options.Manager.StartNmapProfile(c.Param("id"), selected, request.Profile)
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
	c.Header("Location", "/api/nmap/"+job.ID)
	c.JSON(http.StatusAccepted, job)
}
