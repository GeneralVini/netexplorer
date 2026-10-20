# Saved inventory analysis

**Save results** downloads `netexplorer-inventory.json`. It captures the current partial or completed discovery state, hosts, logical identities, MAC/vendor evidence, mDNS hints, TCP observations, warnings and timestamps. Retained NSE jobs and Windows assessments are included when available. Credentials and SSH keys are never included. The schema has an explicit version and export timestamp.

**Load results** accepts this JSON format (up to 16 MiB), validates endpoints and bounded inventory records, and opens a read-only analysis view. Stop discovery and finish or cancel TCP/NSE jobs before loading. The import does not replace the scan manager's inventory, resume discovery, queue Auto TCP or create network targets. Filters, pagination, JSON dialogs and saved TCP details remain available. Saved Windows assessment JSON is available for hosts with endpoint inventory. **Live inventory** returns to the current scan inventory; it does not start a scan.

The loaded view is shared by clients of this local app instance and remains in memory until cleared or the app restarts. The downloaded file provides persistence across restarts. Loading invalid files leaves the previous view intact. All POST actions use the existing CSRF/same-origin policy; scan, inspection and assessment writes are rejected while analyzing saved data. Historical checks are evidence, not newly executed verification. Save while a job is running records a partial result.

Routes: `GET /api/snapshots/export`, `POST /api/snapshots/load`, `POST /api/snapshots/live`. Imports use a strict typed decoder, bounded bodies, endpoint/identifier validation and escaped presentation. No filenames or filesystem paths are accepted from the browser. Oversized exports return an error instead of downloading a file that cannot be reloaded.

Save results and Load results are always visible above the inventory, including before discovery starts. Continuous discovery supports Pause/Resume without replacing its session or inventory. Pause lets active bounded discovery/TCP work finish and gates new work; completed TCP inspections remain recorded and are not repeated on resume. Stop also retains the current results, but a new Start creates a separate session. Save a JSON snapshot before restarting the application.

LAN discovery uses Nmap host-only batches of up to 32 validated addresses, four workers, and 20-second subprocess deadlines within the existing 60-second pass limit. Successful batches remain available when another batch fails. ARP, ICMP and mDNS evidence is merged independently. No NSE or vulnerability checks are introduced by discovery.

Transient global LAN discovery warnings describe the most recent pass and expire after a successful new pass. Historical per-host and TCP errors remain retained.
