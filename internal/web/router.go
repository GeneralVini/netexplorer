// Package web provides the Gin HTTP routes and HTML presentation layer.
package web

import (
	"context"
	"github.com/gin-gonic/gin"
	"html/template"
	"net/http"
	"netexplorer/internal/discovery/network"
	"netexplorer/internal/inventory"
	"netexplorer/internal/tools"
)

// Router builds the home, health, and interface routes for the given version.
// Supplying Options enables protected scan, inventory, SSE, and local asset routes.
// It calls interfaces for each interface request, masking internal errors in HTTP
// responses. The caller is responsible for listener limits, timeouts, and access
// control. Router sets Gin release mode and must be called during initialization.
func Router(version string, interfaces func() ([]network.Interface, error), options ...Options) http.Handler {
	arpInfo := tools.InspectARP(context.Background())
	runtimeTools := tools.Discover("nmap", "smbclient", "ssh", "pwsh")
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.SetHTMLTemplate(template.Must(template.New("home").Funcs(template.FuncMap{"inventoryView": inventoryView, "serviceName": serviceName, "portPreview": portPreview, "stateIcon": stateIcon, "mediaLink": mediaLink}).Parse(homeTemplate + devicesTemplate)))
	var scans *scanHTTP
	if len(options) > 0 && options[0].Manager != nil {
		scans = newScanHTTP(options[0], interfaces)
		router.Use(scans.protect)
		scans.install(router)
		scans.installVendors(router)
		scans.installSnapshots(router)
	}
	router.GET("/", func(c *gin.Context) {
		data := gin.H{"Version": version, "Devices": []inventory.Device{}, "Hosts": []inventory.Host{}, "ARP": arpInfo, "RuntimeTools": runtimeTools}
		if scans != nil {
			data["Token"] = scans.token
			data["DefaultInterface"] = scans.options.DefaultInterface
			data["Interfaces"], _ = interfaces()
			data["Offline"] = scans.offline()
			data["NmapAvailable"] = scans.options.Manager.NmapAvailable() && !scans.offline()
			data["DiscoveryAvailable"] = scans.options.Manager.DiscoveryAvailable()
			if job, ok := scans.options.Manager.LatestCheck(); ok && job.Status == "running" {
				data["LatestCheck"] = job.ID
			}
			if job, ok := scans.options.Manager.LatestNmap(); ok && job.Status == "running" {
				data["LatestNmap"] = job.ID
			}
			if latest, ok := scans.current(); ok {
				if !scans.offline() {
					data["LatestScan"] = latest.ID
				}
				data["Devices"] = latest.Report.Devices
				data["Hosts"] = latest.Report.Hosts
			}
		}
		c.HTML(http.StatusOK, "home", data)
	})
	router.GET("/api/tools/arp", func(c *gin.Context) { c.JSON(http.StatusOK, arpInfo) })
	router.GET("/api/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok", "version": version}) })
	router.GET("/api/interfaces", func(c *gin.Context) {
		items, err := interfaces()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to enumerate network interfaces"})
			return
		}
		c.JSON(http.StatusOK, items)
	})
	return router
}
