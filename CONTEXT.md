# Plan: net-scan

> **Repo:** `pwnbox_modules/net_scan`  
> **Language:** Go  
> **Binary name:** `net-scan`  
> **DB path:** `~/.pwnbox/network.db`

---

## Purpose

A Go wrapper around `nmap` that:
1. Runs structured nmap scans (full port → service detection pipeline) against a target or subnet
2. Stores all results in a SQLite database at `~/.pwnbox/network.db`
3. Ingests output from other scanners (SharpScan available here: https://github.com/zeisroc/SharpScan; executed on victim machines) into the same DB
4. Is consumed by `credops` (to know which ports are open) and `pwnbox-tools` (for the full picture)

---

## Database Schema (`~/.pwnbox/network.db`)

```sql
CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    hostname    TEXT,
    os_guess    TEXT,
    source      TEXT NOT NULL,   -- 'nmap', 'sharpscan', 'manual'
    project     TEXT,            -- engagement/challenge label (optional)
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip)
);

CREATE TABLE IF NOT EXISTS open_ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'tcp',  -- tcp / udp
    state       TEXT NOT NULL DEFAULT 'open', -- open / filtered
    service     TEXT,       -- e.g. 'http', 'mssql', 'smb'
    version     TEXT,       -- banner/version string from -sV
    source      TEXT NOT NULL,
    scanned_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, port, protocol)
);
```

---

## CLI Design

### Top-level command
```
net-scan [command] [flags]
```

### Subcommands

#### `scan` — Run nmap against a target
```
net-scan scan --target <IP|CIDR|file> [flags]
```

**Flags:**
```
--target, -t    string   Target IP, CIDR, or file with IPs (required)
--project       string   Label for this scan (e.g. "challenge6")
--full                   Run full pipeline: all-ports → service detection (default)
--ports-only             Only run all-ports scan (skip -sV), faster
--proxy         string   Route via SOCKS5 proxy host:port (uses proxychains internally)
--output-dir    string   Directory to save raw nmap XML output (default: ~/.pwnbox/scans/)
--threads       int      nmap --min-rate (default: 5000)
--db            string   Override DB path (default: ~/.pwnbox/network.db)
```

**Scan pipeline (default `--full`):**
1. **Phase 1 — All ports:** `nmap -p- -v --min-rate 5000 -oX <tmp.xml> <target>`
   - When `--proxy` is set, `-sT` (TCP connect scan) is added automatically — SYN scans
     require raw sockets and cannot be routed through a SOCKS proxy via proxychains.
   - Parse open ports from XML
   - Write hosts + open_ports to DB (source: 'nmap', service: null)
   - IP:PORT should be printed to the screen during the scan when there is a new open ports (useful to start working quickly)
2. **Phase 2 — Service detection:** `nmap -p <open_ports> -sV -sC -oX <sV.xml> <target>`
   - Re-parse and update existing open_ports rows with `service` and `version`
   - Update `hosts.os_guess` if OS detection data is present
   - The `smb-os-discovery` NSE script (run via `-sC` when port 445 is open) leaks the
     NetBIOS computer name and domain. Hostname is populated from the `server` elem of
     this script, taking priority over reverse DNS PTR records for Windows machines.
3. Print a summary table at the end: host → open ports with services.

**XML parsing:** Use Go's `encoding/xml` to parse nmap XML output (`<nmaprun>` → `<host>` → `<ports>` → `<port>`).

**Conflict handling:** If a port already exists in the DB for that host, UPDATE (upsert) rather than error.

---

#### `ingest` — Import scanner output from victim machines

```
net-scan ingest [flags]
```

**Supported input formats:**
- `sharpscan` — SharpScan CSV/text output
- `nmap-xml` — Raw nmap XML (for manually run scans)

**Flags:**
```
--file, -f      string   Input file (required, or stdin)
--format        string   Input format: auto, sharpscan, nmap-xml (default: auto)
--source-host   string   IP of the machine that ran the scan (for context)
--project       string   Engagement label
```

**SharpScan format example (to parse):**
```
# $source_ip / $source_hostname
192.168.1.10:80,445
192.168.1.11:22,3389
```

**Behaviour:**
- Parse the source IP and source hostname and add it automatically 
- Parse each host:port pair
- Upsert into `hosts` and `open_ports` tables
- Set `source = 'sharpscan'` and `source_host` in notes
- If there is common open ports between differents scan, the SOURCE should be updated by adding the new source asset.

---

#### `list` — Query the database

```
net-scan list [flags]
```

**Flags:**
```
--host, -h      string   Filter by IP (partial match OK)
--port, -p      int      Filter by port number
--service, -s   string   Filter by service name (e.g. mssql, http, ssh)
--project       string   Filter by project label
--json                   Output as JSON
--markdown, -m           Output as markdown table
```

**Example output (default table):**
```
IP               HOSTNAME    PORT   PROTO  SERVICE   VERSION      SOURCE
192.168.1.10     DC01        445    tcp    smb       Windows SMB  Kali
192.168.1.10     DC01        389    tcp    ldap      -            Kali
192.168.1.10     DC01        88     tcp    kerberos  -            Kali, WEB05
192.168.1.11     SQL27       1433   tcp    mssql     MSSQL 2019   WEB05
192.168.1.11     SQL27       3389   tcp    rdp       -            Kali
```

---

#### `export` — Export hosts/ports for use by other tools

```
net-scan export [flags]
```

**Flags:**
```
--format        string   Output format: targets-file, nxc-list, credops-targets (default: targets-file)
--port, -p      int      Filter by port (e.g. export only hosts with port 445 open)
--service, -s   string   Filter by service
--project       string   Filter by project
```

**Export formats:**
- `targets-file` — one `IP:PORT` per line (for credops `--target` input)
- `nxc-list` — space-separated IPs for nxc
- `credops-targets` — same as targets-file (alias for clarity)

**Example:**
```bash
# Get all hosts with MSSQL open → feed into credops
net-scan export --service mssql --format targets-file > mssql_targets.txt
credops creds test -t mssql_targets.txt -P mssql
```

---

## Project Structure

```
net-scan/
├── cmd/
│   └── net-scan/
│       └── main.go
├── internal/
│   ├── cli/
│   │   ├── root.go
│   │   ├── scan.go
│   │   ├── ingest.go
│   │   ├── list.go
│   │   ├── edit.go
│   │   ├── add.go
│   │   └── export.go
│   ├── db/
│   │   ├── sqlite.go      -- DB init, schema creation, ~/.pwnbox/ dir setup
│   │   ├── operations.go  -- UpsertHost, UpsertPort, ListHosts, ListPorts, tag classification
│   │   └── edit.go        -- UpdateHost, UpdatePort
│   ├── parser/
│   │   ├── nmap_xml.go    -- Parse nmap XML output (including smb-os-discovery hostscripts)
│   │   └── sharpscan.go   -- Parse SharpScan text output
│   ├── runner/
│   │   └── nmap.go        -- Exec nmap, capture XML, call parser; -sT auto-applied with --proxy
│   └── models/
│       └── models.go      -- Host, OpenPort structs
├── Makefile
├── go.mod
└── README.md
```

---

## Integration Points

| Consumer | How it uses net-scan |
|---|---|
| `credops` | Reads `~/.pwnbox/network.db` → filters protocol tests to open ports only |
| `pwnbox-tools` | Calls `net-scan scan` as subprocess; displays results in unified dashboard |
| Manual workflow | `net-scan export --service mssql` → pipe into nxc or credops |

---

## Dependencies

- `github.com/spf13/cobra` — CLI framework
- `modernc.org/sqlite` — Pure Go SQLite (same as credops)
- Standard library `os/exec` for nmap invocation
- `encoding/xml` for nmap XML parsing

---

## Priority Order

1. `scan` command + nmap XML parser + DB schema (core functionality)
2. `list` command (usability)
3. `ingest` command (SharpScan ingestion for internal network pivots)
4. `export` command (integration with credops/nxc)
