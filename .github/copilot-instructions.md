# GitHub Copilot Instructions — `net-scan`

## Project Overview

`net-scan` is a Go CLI tool that wraps `nmap` to run structured port scans,
stores all results in a shared SQLite database (`~/.pwnbox/network.db`), and ingests
output from other scanners (e.g. SharpScan) run on victim machines.

It is part of the **pwnbox** toolchain:
- `credops` reads the DB to scope credential-testing only to open ports.
- `pwnbox-tools` calls `net-scan scan` as a subprocess.

Binary name: `net-scan`

---

## Technology Stack

| Concern       | Choice                                              |
|---------------|-----------------------------------------------------|
| Language      | Go (latest stable)                                  |
| CLI framework | `github.com/spf13/cobra`                            |
| SQLite        | `modernc.org/sqlite` (pure Go, CGO-free)            |
| XML parsing   | `encoding/xml` (stdlib)                             |
| nmap exec     | `os/exec`                                           |

---

## Repository Layout

```
net-scan/
├── cmd/
│   └── net-scan/
│       └── main.go               // entry point: calls cli.Execute()
├── internal/
│   ├── cli/
│   │   ├── root.go               // cobra root command + persistent --db flag
│   │   ├── scan.go               // `scan` subcommand
│   │   ├── ingest.go             // `ingest` subcommand
│   │   ├── list.go               // `list` subcommand
│   │   └── export.go             // `export` subcommand
│   ├── db/
│   │   ├── sqlite.go             // DB init, schema migration, dir creation
│   │   └── operations.go         // UpsertHost, UpsertPort, ListHosts, ListPorts
│   ├── parser/
│   │   ├── nmap_xml.go           // parse nmap XML into []models.Host
│   │   └── sharpscan.go          // parse SharpScan text into []models.Host
│   ├── runner/
│   │   └── nmap.go               // build & exec nmap command, stream output
│   └── models/
│       └── models.go             // Host, OpenPort structs
├── go.mod
└── README.md
```

---

## Database Schema

Located at `~/.pwnbox/network.db` (override via `--db` flag).

```sql
CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    hostname    TEXT,
    os_guess    TEXT,
    source      TEXT NOT NULL,   -- 'nmap', 'sharpscan', 'manual'; comma-separated if multiple
    project     TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip)
);

CREATE TABLE IF NOT EXISTS open_ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    state       TEXT NOT NULL DEFAULT 'open',
    service     TEXT,
    version     TEXT,
    source      TEXT NOT NULL,   -- comma-separated: 'nmap', 'WEB05', etc.
    scanned_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, port, protocol)
);
```

**Upsert rule:** on conflict (ip) or (host_id, port, protocol), UPDATE existing row.
**Source merging:** when a port already exists with source `"nmap"` and a new scan from
`"WEB05"` finds the same port, update source to `"nmap, WEB05"` (append if not present).

---

## CLI Design

### Global flag
```
--db   string   Override DB path (default: ~/.pwnbox/network.db)
```

### `scan` — Run nmap against a target

```
net-scan scan --target <IP|CIDR|file> [flags]
```

Flags:
```
--target, -t    string   Target IP, CIDR, or @file (required)
--project       string   Engagement label
--full                   Full pipeline: all-ports → service detection (default: true)
--ports-only             Skip -sV / -sC phase (faster)
--proxy         string   Route via SOCKS5 host:port using proxychains
--output-dir    string   Directory for raw nmap XML (default: ~/.pwnbox/scans/)
--threads       int      --min-rate value (default: 5000)
```

**Scan pipeline (full mode):**
1. Phase 1 — `sudo nmap -p- --min-rate <threads> -oX <tmp.xml> <target>`
   - Stream output; print newly discovered `IP:PORT` lines in real time.
   - Parse XML → upsert hosts + ports (source: 'nmap', service: null).
2. Phase 2 — `sudo nmap -p <open_ports> -sV -sC -oX <sV.xml> <target>`
   - Parse XML → update service + version fields; update os_guess if present.
3. Print compact summary table: `IP | PORT | PROTO | SERVICE | VERSION`.

**Privilege:** always prepend `sudo` to nmap invocations; if sudo requires a password
the terminal will prompt naturally (inherit stdin/stdout/stderr of the parent process).

**Proxy:** when `--proxy host:port` is given, prepend `proxychains -q` before `sudo nmap`.

### `ingest` — Import scanner output from victim machines

```
net-scan ingest [flags]
```

Flags:
```
--file, -f      string   Input file path (or stdin if omitted)
--format        string   auto | sharpscan | nmap-xml (default: auto)
--source-host   string   Hostname/IP of the machine that ran the scan
--project       string   Engagement label
```

**SharpScan format:**
```
# 192.168.1.5 / WEB05
192.168.1.10:80,445
192.168.1.11:22,3389
```
- First line `# $ip / $hostname` is parsed automatically as source context.
- `--source-host` overrides the auto-parsed value.

**Behaviour:**
- Upsert hosts and ports with source = `"<source-host>"` (e.g. `"WEB05"`).
- If a port already exists from a different source, append source name.

### `list` — Query the database

```
net-scan list [flags]
```

Flags:
```
--host, -H      string   Filter by IP (partial/prefix match)
--port, -p      int      Filter by port number
--service, -s   string   Filter by service name (partial match)
--project       string   Filter by project label
--json          bool     Output as JSON
--markdown, -m  bool     Output as markdown table
```

Default output (aligned table):
```
IP               HOSTNAME    PORT   PROTO  SERVICE   VERSION      SOURCE
192.168.1.10     DC01        445    tcp    smb       Windows SMB  nmap, WEB05
```

### `export` — Export for other tools

```
net-scan export [flags]
```

Flags:
```
--format        string   targets-file | nxc-list | credops-targets (default: targets-file)
--port, -p      int      Filter by port
--service, -s   string   Filter by service
--project       string   Filter by project
```

Formats:
- `targets-file` / `credops-targets` — one `IP:PORT` per line
- `nxc-list` — space-separated IPs

---

## Models

```go
// internal/models/models.go

type Host struct {
    ID        int64
    IP        string
    Hostname  string
    OSGuess   string
    Source    string
    Project   string
    CreatedAt time.Time
    UpdatedAt time.Time
    Ports     []OpenPort
}

type OpenPort struct {
    ID        int64
    HostID    int64
    Port      int
    Protocol  string
    State     string
    Service   string
    Version   string
    Source    string
    ScannedAt time.Time
}
```

---

## Code Conventions

- All packages under `internal/` — nothing exported unnecessarily.
- Error handling: always wrap errors with `fmt.Errorf("context: %w", err)`.
- Use `cobra.Command` `RunE` (not `Run`) so errors propagate cleanly.
- DB connection is opened once in root command and passed via `cobra.Command.PersistentPreRunE`.
- Use `*sql.DB` directly (no ORM). Write raw SQL with named parameters where possible.
- Output formatting: use `text/tabwriter` for table output.
- Prefer streaming nmap output to stdout in real time (`cmd.Stdout = os.Stdout` during phase 1).
- All file paths that start with `~` must be expanded with `os.UserHomeDir()`.
- `sudo` is always prepended to nmap calls; `proxychains -q` is prepended when `--proxy` is set.

---

## Integration Notes

- `credops` reads `~/.pwnbox/network.db` directly — do not change the schema without coordinating.
- When building, the binary should be installable via `go install ./cmd/net-scan`.
- No CGO: use `modernc.org/sqlite` (pure Go) to keep the binary fully static.
