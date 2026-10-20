package web

import (
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"
	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/nmap"
	"netexplorer/internal/enrichment/services"
	"netexplorer/internal/inventory"
	"netexplorer/internal/scanner"
)

// portPreview keeps host cards bounded even when all TCP ports are observed.
func portPreview(host inventory.Host) []services.Row {
	// Select four observations before annotating, keeping allocation independent of scan size.
	preview := make([]nmap.Port, 0, 5)
	for _, port := range host.Ports {
		preview = append(preview, port)
		sort.SliceStable(preview, func(i, j int) bool {
			if (preview[i].State == "open") != (preview[j].State == "open") {
				return preview[i].State == "open"
			}
			return preview[i].Number < preview[j].Number
		})
		if len(preview) > 4 {
			preview = preview[:4]
		}
	}
	result := make([]services.Row, 0, len(preview))
	for _, port := range preview {
		result = append(result, services.Annotate(host.IP, port))
	}
	return result
}

// stateIcon uses shapes as well as colors; unknown states remain accessible.
func stateIcon(state string) string {
	switch state {
	case "open":
		return "✓"
	case "closed":
		return "×"
	case "filtered":
		return "◆"
	case "open|filtered":
		return "◈"
	case "unfiltered":
		return "○"
	case "closed|filtered":
		return "⊗"
	default:
		return "?"
	}
}

// serviceDetails returns detached inventory evidence and reviewed offline references.
func (h *scanHTTP) serviceDetails(c *gin.Context) {
	archive := h.saved()
	hosts := h.hosts()
	if archive != nil {
		hosts = archive.Scan.Report.Hosts
	}
	for _, host := range hosts {
		if host.ID != c.Param("id") {
			continue
		}
		rows := make([]services.Row, 0, len(host.Ports))
		for _, port := range host.Ports {
			rows = append(rows, services.Annotate(host.IP, port))
		}
		jobs := h.options.Manager.CheckJobs(host.ID)
		checks := nmap.CheckCatalog()
		if archive != nil {
			for i := range rows {
				rows[i].Checks = nil
			}
			jobs = archive.Checks[host.ID]
		}
		c.JSON(http.StatusOK, gin.H{"offline": archive != nil, "id": host.ID, "ip": host.IP, "coverage": host.Coverage, "observed_at": host.EnrichedAt, "ports": rows, "catalog_reviewed": "2026-10-02", "checks": jobs, "check_catalog": checks})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
}

// listShares validates explicit authorization, a fixed SMB port and the current interface.
func (h *scanHTTP) listShares(c *gin.Context) {
	var request struct {
		Authorized bool `json:"authorized"`
		Port       int  `json:"port"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid share request"})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF || !request.Authorized || (request.Port != 445 && request.Port != 139) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "authorization and an observed SMB port are required"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan interface is unavailable"})
		return
	}
	shares, err := h.options.Manager.ListShares(c.Request.Context(), c.Param("id"), selected, request.Port)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, scanner.ErrBusy) {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"shares": shares})
}

// mediaLink permits only generated credential-free RTSP links to literal IPv4 endpoints.
func mediaLink(raw string) template.URL {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "rtsp" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/" {
		return ""
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.Is4() || ip.String() != u.Hostname() {
		return ""
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return ""
		}
	}
	// #nosec G203 -- Fixed RTSP scheme, canonical literal IPv4, numeric port, root path, no credentials/query/fragment.
	return template.URL(raw)
}
