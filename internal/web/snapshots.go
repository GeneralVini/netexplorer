package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"netexplorer/internal/enrichment/windows"
	"netexplorer/internal/scanner"
)

// snapshot is a versioned, portable inventory export, never a source of scan targets.
type snapshot struct {
	// Version identifies the supported file schema.
	Version int `json:"version"`
	// SavedAt records when the current partial or completed result was exported.
	SavedAt time.Time `json:"saved_at"`
	// Checks preserves manual NSE results keyed by inventory host ID.
	Checks map[string][]scanner.CheckJob `json:"checks,omitempty"`
	// Windows preserves imported or collected endpoint assessments.
	Windows map[string]windows.Report `json:"windows,omitempty"`
	// Scan retains inventory, port evidence, warnings and discovery timestamps.
	Scan scanner.State `json:"scan"`
}

// current keeps imported analysis separate from the scan manager's live inventory.
func (h *scanHTTP) current() (scanner.State, bool) {
	h.archiveMu.RLock()
	defer h.archiveMu.RUnlock()
	if h.archive != nil {
		return h.archive.Scan, true
	}
	return h.options.Manager.Latest()
}

func (h *scanHTTP) saved() *snapshot {
	h.archiveMu.RLock()
	defer h.archiveMu.RUnlock()
	return h.archive
}
func (h *scanHTTP) offline() bool { return h.saved() != nil }

func (h *scanHTTP) installSnapshots(router *gin.Engine) {
	router.GET("/api/snapshots/windows/:id", func(c *gin.Context) {
		if archive := h.saved(); archive != nil {
			if report, ok := archive.Windows[c.Param("id")]; ok {
				c.JSON(http.StatusOK, report)
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "saved Windows assessment not found"})
	})
	router.GET("/api/snapshots/export", func(c *gin.Context) {
		archive := h.saved()
		state, ok := h.options.Manager.Latest()
		if archive != nil {
			state = archive.Scan
			ok = true
		}
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "no inventory available"})
			return
		}
		c.Header("Content-Disposition", `attachment; filename="netexplorer-inventory.json"`)
		value := snapshot{Version: 1, SavedAt: time.Now().UTC(), Scan: state, Checks: map[string][]scanner.CheckJob{}, Windows: map[string]windows.Report{}}
		if archive != nil {
			value.Checks = archive.Checks
			value.Windows = archive.Windows
		} else {
			for _, host := range state.Report.Hosts {
				value.Checks[host.ID] = h.options.Manager.CheckJobs(host.ID)
				if report, ok := h.options.Manager.WindowsReport(host.ID); ok {
					value.Windows[host.ID] = report
				}
			}
		}
		data, err := json.Marshal(value)
		if err != nil || len(data) > 16<<20 {
			c.Header("Content-Disposition", "")
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "inventory snapshot exceeds 16 MiB"})
			return
		}
		c.Data(http.StatusOK, "application/json", data)
	})
	router.POST("/api/snapshots/load", func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<20)
		var value snapshot
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&value); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid snapshot JSON or file exceeds 16 MiB"})
			return
		}
		if decoder.Decode(new(any)) != io.EOF || validateSnapshot(value) != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported or invalid inventory snapshot"})
			return
		}
		if state, ok := h.options.Manager.Latest(); ok && state.Status == "running" {
			c.JSON(http.StatusConflict, gin.H{"error": "stop discovery before loading a saved inventory"})
			return
		}
		if job, ok := h.options.Manager.LatestNmap(); ok && job.Status == "running" {
			c.JSON(http.StatusConflict, gin.H{"error": "wait for or cancel TCP inspection before loading"})
			return
		}
		if job, ok := h.options.Manager.LatestCheck(); ok && job.Status == "running" {
			c.JSON(http.StatusConflict, gin.H{"error": "wait for or cancel the current check before loading"})
			return
		}
		h.archiveMu.Lock()
		h.archive = &value
		h.archiveMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"saved_at": value.SavedAt, "offline": true})
	})
	router.POST("/api/snapshots/live", func(c *gin.Context) {
		h.archiveMu.Lock()
		h.archive = nil
		h.archiveMu.Unlock()
		c.Status(http.StatusNoContent)
	})
}

var snapshotID = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)

// validateSnapshot bounds records and ensures imported endpoints are display-only IPv4.
func validateSnapshot(value snapshot) error {
	report := value.Scan.Report
	if value.Version != 1 || len(report.Hosts) > 1024 || len(report.Devices) > 4096 || len(report.Warnings) > 4096 {
		return fmt.Errorf("snapshot limits exceeded")
	}
	validIP := func(value string) bool {
		ip := net.ParseIP(value)
		return ip != nil && ip.To4() != nil && ip.IsGlobalUnicast() && !ip.IsLoopback()
	}
	seen := map[string]bool{}
	for _, host := range report.Hosts {
		if !snapshotID.MatchString(host.ID) || seen[host.ID] || !validIP(host.IP) || len(host.Ports) > 65535 {
			return fmt.Errorf("invalid snapshot host")
		}
		seen[host.ID] = true
		if host.MAC != "" {
			mac, err := net.ParseMAC(host.MAC)
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
				return fmt.Errorf("invalid snapshot MAC")
			}
		}
		for _, port := range host.Ports {
			if port.Number < 1 || port.Number > 65535 || port.Protocol != "tcp" {
				return fmt.Errorf("invalid snapshot port")
			}
		}
	}
	if len(value.Checks) > 1024 || len(value.Windows) > 1024 {
		return fmt.Errorf("too many assessment records")
	}
	for id, jobs := range value.Checks {
		if !seen[id] || len(jobs) > 256 {
			return fmt.Errorf("invalid assessment host")
		}
		for _, job := range jobs {
			if job.HostID != id || !snapshotID.MatchString(job.ID) || !validIP(job.IP) {
				return fmt.Errorf("invalid check evidence")
			}
		}
	}
	for id := range value.Windows {
		if !seen[id] {
			return fmt.Errorf("invalid Windows assessment host")
		}
	}
	seen = map[string]bool{}
	for _, device := range report.Devices {
		if !snapshotID.MatchString(device.ID) || seen[device.ID] || !validIP(device.IP) || len(device.Services) > 1024 {
			return fmt.Errorf("invalid snapshot device")
		}
		seen[device.ID] = true
	}
	return nil
}
