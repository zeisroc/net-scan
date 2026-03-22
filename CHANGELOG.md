# Changelog

All notable changes to **net-scan** are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2026-03-22] — continued

### Added
- **nmap command templates** — `~/.pwnbox/net-scan.yaml` is created on first run
  with annotated default templates for Phase 1, Phase 2, and version scans.
  Placeholders: `{{TARGET}}`, `{{OUTPUT}}`, `{{PORTS}}`, `{{RATE}}`.
  Edit the file to customise nmap flags without touching the source code.
- **`--config` global flag** — override the config file path
  (default: `~/.pwnbox/net-scan.yaml`).

### Added
- **`domain` field on `hosts`** — new column (auto-migrated, `DEFAULT ''`) storing
  the Windows AD domain for a host (e.g. `cowmotors.com`).
- **`Host.Domain`** in `models.go`; propagated through `UpsertHost`, `HostRow`,
  `ListHosts`, `HostUpdate`/`UpdateHost`.
- **Domain extraction from `smb-os-discovery`** — parser reads the `domain` elem
  from the nmap hostscript output and stores it in `Host.Domain`.
- **Domain saved from `nxc` SMB probe** — `probeSMBHostnames` now persists
  `SMBInfo.Domain` alongside the computer name.
- **DOMAIN column in `net-scan list`** — shown between HOSTNAME and PWND in the
  terminal table and markdown output; included in JSON output automatically.
  Rendered dim when unknown (`—`).
- **`edit --domain`** flag for manually setting or clearing the AD domain of a host.

## [2026-03-22]

### Added
- **`internal/runner/netexec.go`** — `RunNxcSMB(ip, proxy)` probes Windows hosts
  via `nxc smb <ip>` to extract computer name, domain, and OS string directly from
  the SMB negotiate response (no authentication required). Returns `nil` silently if
  `nxc` is not installed.
- **`internal/runner/netexec_test.go`** — unit tests for `parseNxcSMBOutput`.
- **`probeSMBHostnames()`** helper in `scan.go` — after Phase 2 (and after each
  `scan enrich` host), automatically probes any host with `445/tcp` open and no
  hostname. Updates `hostname`, `os_guess`, and merges `"nxc"` into the source field.

### Why
`smb-os-discovery` NSE script depends on a successful SMB session and silently fails
on some Windows configurations (signing enforcement, version negotiation). `nxc` reads
the computer name from the raw negotiate response, which always fires on reachable hosts.

---

## [2026-03-21]

### Added
- **`scan enrich` subcommand** — runs Phase 2 (`nmap -p <ports> -sV -sC`) per-host
  against all hosts where `phase2_done = 0` (e.g. imported via SharpScan or scanned
  with `--ports-only`). Marks `phase2_done = 1` on success.
  Flags: `--project`, `--all` (re-run even if already enriched), `--proxy`,
  `--output-dir`.
- **`phase2_done` column** on `hosts` table (auto-migration, `DEFAULT 0`).
- **`db.ListUnenrichedTargets()`** — queries TCP ports for hosts with `phase2_done = 0`.
- **`db.MarkPhase2Done()`** — sets `phase2_done = 1` for a given host IP.
- Normal `scan` pipeline now marks all Phase 1 hosts as `phase2_done = 1` after Phase 2
  completes successfully.

### Fixed
- **Proxy scans broken** — all nmap phases (`RunAllPorts`, `RunServiceDetection`,
  `RunVersionDetection`) now add `-sT` (TCP connect scan) automatically when `--proxy`
  is set. SYN scans use raw sockets that bypass the SOCKS stack and produce no results
  through proxychains.
- **Windows hostname missing** — nmap XML parser now reads `<hostscript>` elements and
  extracts `server` (computer name) and `os` from the `smb-os-discovery` script output,
  taking priority over reverse-DNS PTR records. Falls back to `fqdn` elem if `server`
  is absent.

### Fixed (minor)
- Typo `"UNKNOW"` → `"UNKNOWN"` in `classifyTags()` fallback in `operations.go`.

### Changed
- **`CONTEXT.md`** — updated binary name (`network-scanner` → `net-scan`), project
  structure, and pipeline notes to reflect current implementation.
- **`README.md`** — added notes on automatic `-sT` with `--proxy`, SMB hostname
  discovery via `smb-os-discovery`, and new `scan enrich` subcommand docs.

---

## [2026-03-15]

### Added
- **`edit` command** — update host/port metadata without re-scanning:
  hostname, tag, OS guess, project, source, pwned status, port service/version/state.
- **`pwned` tracking** — `host_metadata.pwned` boolean column; `net-scan list` renders
  pwned hosts in bold red with a `☠  PWNED` marker.
- **`add` command** — seed the database with IPs before scanning (source: `manual`);
  accepts single IP or file with one IP per line.
- **Version scan** (`scan version`) — database-driven `nmap -sV` against all stored
  open ports grouped per host, without a discovery phase.
- **Auto-tagging** in `classifyTags()` — host tags derived from open ports and service
  names: DC, Windows, Linux, HTTP, MSSQL, DNS, LDAP, FTP, SMTP, POP3, IMAP, NFS,
  MYSQL, POSTGRES, REDIS, ORACLE, VNC, SNMP. Manual tags via `edit --tag` are additive.
- Rich terminal output in `list` — host cards with bold cyan IPs, yellow tags, green
  port names, `host_metadata` integration (pwned flag, manual tags).

---

## [2026-03-06]

### Fixed
- **Phase 2 false positives** — Phase 2 results are now filtered against the Phase 1
  port set; nmap cannot introduce ports that were not confirmed in Phase 1.
- Phase 1 now prints only `Discovered open port` lines by default (using `stdbuf -oL`
  for line-buffered output); full output available via `-v`.

---

## [2026-03-05] — Initial implementation

### Added
- **`models`** — `Host` and `OpenPort` structs.
- **`db`** — SQLite schema (`hosts`, `open_ports`, `host_metadata`), `Open()` with
  `~` path expansion, WAL mode, foreign keys. `UpsertHost`, `UpsertPort`,
  `UpsertHosts`, `MergeSource` (comma-separated source deduplication),
  `ListPorts`, `ListHosts`, `ListVersionTargets`, `GetHostID`.
- **`runner`** — nmap executor: `RunAllPorts` (Phase 1), `RunServiceDetection`
  (Phase 2), `RunVersionDetection`; `buildArgs` with `sudo` + optional
  `proxychains -q` prefix; `filterDiscovered` for live port streaming.
- **`parser/nmap_xml`** — parse nmap XML into `[]models.Host`; extracts IP, hostname
  (PTR priority), OS guess, open ports with service/version.
- **`parser/sharpscan`** — parse SharpScan text output; auto-detects source IP and
  hostname from the `# ip / hostname` header.
- **`cli/scan`** — two-phase nmap scan pipeline with live port output and DB
  persistence. Flags: `-t`, `--project`, `--ports-only`, `--proxy`, `--output-dir`,
  `--threads`.
- **`cli/ingest`** — import SharpScan or nmap XML with source merging and format
  auto-detection from file extension.
- **`cli/list`** — query database with filters (`--host`, `--port`, `--service`,
  `--project`); table / JSON (`--json`) / markdown (`-m`) output.
- **`cli/export`** — export filtered results as `targets-file` (IP:PORT), `nxc-list`
  (space-separated IPs), or `credops-targets`.
- **`cli/root`** — cobra root command; persistent flags: `--db`, `-d`/`--debug`,
  `-v`/`--verbose`; `openDB` `PersistentPreRunE` hook.
- **`Makefile`** — `make build` outputs binary to `bin/net-scan`.
- **`README.md`** — installation, usage examples, and integration notes.
