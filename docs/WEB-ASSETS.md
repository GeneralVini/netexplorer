# Embedded web assets

Bootstrap 5.3.8 CSS is from [twbs/bootstrap](https://github.com/twbs/bootstrap/tree/v5.3.8/dist/css), under the MIT license. HTMX 2.0.8 is from [bigskysoftware/htmx](https://github.com/bigskysoftware/htmx/tree/v2.0.8/dist), under the Zero-Clause BSD license. Upstream licenses are preserved alongside the assets. Downloads use pinned official repository tags; dependencies are embedded, with no runtime CDN requests.

| File | SHA-256 |
| --- | --- |
| `bootstrap.min.css` | `d85327d99c7a3ee1f9b5d0500d1370acea3ad2db39c163c2f51f232baedbdede` |
| `bootstrap.LICENSE` | `4620c84ad5ce8602ff65640ed6b7c8b78ebb9e036584f0ebc1ccc88206a4bb51` |
| `htmx.min.js` | `22283ef68cb7545914f0a88a1bdedc7256a703d1d580c1d255217d0a50d31313` |
| `htmx.LICENSE` | `d3d2456f76414f2456104660ebd65aff1c04cd7966b942bdabd63f3cdb316a38` |

When updating, review upstream releases, replace the pinned files and licenses, regenerate these hashes, and verify the UI and security gates. Bootstrap JavaScript is not required by the current components. Application JavaScript is maintained in this repository.

## Manufacturer logos and device illustrations

Twenty manufacturer logos are vendored from [Simple Icons 16.33.0](https://github.com/simple-icons/simple-icons/tree/e01988cc57a3aca39621023f9881e9b733ebcd77/icons), pinned to commit `e01988cc57a3aca39621023f9881e9b733ebcd77`. The CC0 license and upstream trademark disclaimer are preserved under internal/web/assets/icons. Brand marks identify advertised manufacturers; they do not imply affiliation or certification. The asset manifest records upstream source URLs, original SHA-256 hashes, local hashes, and colors. Sony and Synology use darker colors for contrast on white cards; SVG paths remain unchanged.

Supported logos: Apple, ASUS, Cisco, Dell, Google, HP, Huawei, Intel, Intelbras, Lenovo, LG, LITEON, NETGEAR, Nokia, Nintendo, Panasonic, QNAP, Samsung, Sony, Synology, TP-Link, Ubiquiti, and Xiaomi. Manufacturers outside the catalog keep their advertised name and a neutral network icon. Missing manufacturer metadata uses an unknown label; device names are not used to guess a brand.

The catalog uses explicit normalized aliases in internal/web/presentation.go. Same-IP embedded devices may inherit the displayed brand from an existing parent, with a visible source label; original inventory attributes/evidence remain unchanged. Cross-IP links are rejected; cycle checks and a depth limit bound ancestor traversal. Extending the catalog requires a pinned, reviewed local SVG, provenance in the manifest, and explicit aliases. Public asset routes use an allowlist and do not expose licenses or the manifest.

Device illustrations in devices.svg and application styling in app.css are original repository assets. Illustrations use advertised UPnP types to distinguish routers, access points, media renderers, media servers, printers, and generic network devices. No device-advertised image or manufacturer URL is fetched for display. All assets work offline and are embedded in the Go binary.

Nintendo uses the Nintendo wordmark from the pinned Simple Icons 13.0.0 tag (it is absent from 16.33.0), with red fill. Its separate provenance and hashes are recorded in the manifest.

MAC addresses are displayed in uppercase without modifying inventory evidence. Valid globally administered Ethernet MACs link to the fixed HTTPS MacVendors API in a new tab as a manual second vendor source. The tooltip explains that opening the link sends the MAC to an external service. Private/randomized and multicast addresses do not receive registry links. No automatic external requests occur during discovery and local vendor evidence is preserved. [API documentation](https://macvendors.com/api) specifies 1 request/second and 1,000 requests/day without an API key; HTTP 404 means no match and 429 means rate limiting.

Additional registry aliases cover Intel Corporate and Samsung Electro-Mechanics (Thailand). Intelbras uses a sanitized SVG from its official manuals site; LITEON uses the historical wordmark from Wikimedia Commons (simple-logo public-domain attribution on the source page). The manifest records source URLs and hashes. Sanitized SVGs retain geometry/fill and omit declarations, metadata, scripts and external references. Manufacturer viewBoxes are cropped around their marks to avoid excessive whitespace; all brand marks use a larger contained display box. Card details use Services, TCP ports and Identity tabs with a single visible panel. All panels start collapsed; selection survives inventory updates. Clicking the active tab hides its panel. Identity uses a compact key/value layout with expandable evidence and bounded scrolling; TCP previews have no internal scrollbar. Tabs support arrow keys, Home and End.

## Missing manufacturer workflow

When a new manufacturer name is reported, check normalized aliases before downloading another logo. Reuse the reviewed local asset for a confirmed alias (for example, TP-Link Systems Inc.). If no asset exists, obtain the brand mark from an official source or a licensed icon catalog, sanitize SVG geometry, record source/license and original/local hashes in the manifest, and add an explicit alias. Rebuild the embedded assets and verify the card. Network-advertised URLs are not logo sources. This is a maintenance workflow; scans do not download arbitrary images or modify the installed binary.

Observed RTSP TCP services expose credential-free `rtsp://` links in card previews and the services dialog, with copy support for external clients such as VLC. Port 554 uses the default RTSP port; other observed ports are included explicitly. A link does not confirm anonymous playback. No stream path dictionary, authentication attempts or media playback runs automatically.

Inventory cards are grouped by IP and sorted by numeric address. The gateway/root identity represents each host; other logical UPnP identities remain available under Identity and through their original Device JSON links. Grouped service lists retain all advertised entries. Logical-device totals still count the original inventory records.
