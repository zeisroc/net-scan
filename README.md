# net-scan

A Go wrapper around `nmap` that runs structured port scans, stores all results in a shared SQLite database (`~/.pwnbox/network.db`), ingests output from [SharpScan](https://github.com/7own/SharpScan) executed on victim machines, and exports data for `credops` and `nxc`.

Part of the **pwnbox** toolchain.

---

## Installation

```bash
go install github.com/pwnbox/net_scan/cmd/net-scan@latest
```

Or build from source:

```bash
git clone <repo>
cd net_scan
make build          # output: bin/net-scan
# or directly:
go build -o net-scan ./cmd/net-scan/
```

> **Requires:** `nmap` and `sudo` on PATH. `proxychains` only needed when `--proxy` is used.

---

## Database

All results are stored in `~/.pwnbox/network.db` (SQLite). Override with `--db <path>`.

The `credops` tool reads this database directly to scope credential tests to open ports only.

---

## Global Flags

These flags are available on every command:

```
--db string         Override SQLite DB path (default: ~/.pwnbox/network.db)
-d, --debug         Print the exact nmap command before executing
-v, --verbose       Print full nmap output (default: Phase 1 shows discovered ports only, Phase 2 is silent)
```

---

## Commands

### `scan` — Run nmap against a target

Two-phase pipeline under `sudo`:

1. **Phase 1** — `nmap -p- -v --min-rate 5000` — discovers all open TCP ports  
   By default only `Discovered open port` lines are printed live. Use `-v` for full nmap output.
2. **Phase 2** — `nmap -p <ports> -sV -sC` on the exact ports found per host — enriches with service/version data  
   Silent by default; use `-v` for full output. Results are strictly filtered to ports confirmed in Phase 1 — Phase 2 cannot introduce new ports.

```bash
# Full scan (default)
net-scan scan -t 10.10.10.1

# Scan a subnet, tag with project label
net-scan scan -t 192.168.1.0/24 --project corp-internal

# Comma-separated targets
net-scan scan -t 10.0.0.1,10.0.0.2,192.168.1.0/24

# File with one target per line
net-scan scan -t targets.txt

# Fast port-only scan (skip service detection)
net-scan scan -t 10.10.10.1 --ports-only

# Route through proxychains (SOCKS5 pivot)
net-scan scan -t 172.16.0.0/24 --proxy 127.0.0.1:1080

# Custom rate and output directory
net-scan scan -t 10.0.0.1 --threads 1000 --output-dir /tmp/scans

# Print nmap commands and full output
net-scan scan -t 10.10.10.1 -d -v
```

**Flags:**
```
-t, --target       Target: IP, CIDR, comma-separated list, or file path (required)
    --project      Engagement label
    --ports-only   Skip -sV/-sC phase (Phase 1 only)
    --proxy        SOCKS5 host:port (via proxychains)
    --output-dir   Directory for raw nmap XML (default: ~/.pwnbox/scans/)
    --threads      nmap --min-rate (default: 5000)
```

#### `scan version` — Re-scan stored assets with `-sV`

Runs a database-driven version scan against all stored open ports in `~/.pwnbox/network.db`.
It does not perform discovery first; instead, it reuses the current `host:port` inventory and
executes `nmap -sV` per host on those exact ports.

```bash
# Re-scan every stored asset and known port with version detection
net-scan scan version

# Route the version scan through a SOCKS5 pivot
net-scan scan version --proxy 127.0.0.1:1080

# Save XML output somewhere else
net-scan scan version --output-dir /tmp/scans
```

**Flags:**
```
    --proxy        SOCKS5 host:port (via proxychains)
    --output-dir   Directory for raw nmap XML (default: ~/.pwnbox/scans/)
```

---

### `ingest` — Import scanner output from victim machines

Import [SharpScan](https://github.com/7own/SharpScan) output or raw nmap XML collected from pivot machines.

Format is auto-detected from the file extension: `.xml` → `nmap-xml`, anything else → `sharpscan`. When reading from stdin, `sharpscan` is assumed.

```bash
# Ingest SharpScan output (auto-detected)
net-scan ingest -f sharpscan_output.txt

# Override detected source hostname
net-scan ingest -f scan.txt --source-host WEB05 --project corp-internal

# Ingest nmap XML
net-scan ingest -f results.xml --format nmap-xml

# From stdin
cat scan.txt | net-scan ingest --format sharpscan
```

**SharpScan format:**
```
# 192.168.1.5 / WEB05
192.168.1.10:80,445
192.168.1.11:22,3389
```

The `# ip / hostname` header is parsed automatically as the source identifier. `--source-host` overrides the parsed value.  
If a port already exists in the DB from another source, the source field is updated to include both (e.g. `nmap, WEB05`).

**Flags:**
```
-f, --file         Input file path (stdin if omitted)
    --format       auto | sharpscan | nmap-xml (default: auto)
    --source-host  Override source hostname
    --project      Engagement label
```

---

### `list` — Query the database

```bash
# List all known hosts and ports
net-scan list

# Filter by IP prefix
net-scan list --host 192.168.1

# Filter by service
net-scan list --service mssql
net-scan list --service http

# Filter by port
net-scan list --port 445

# Filter by project
net-scan list --project corp-internal

# Output as JSON or markdown
net-scan list --json
net-scan list --markdown
```

**Example output:**
```
IP               HOSTNAME   PWND  TAG                   PORTS
192.168.1.10     DC01        -    DC, Windows, LDAP     88/tcp(kerberos)  │  389/tcp(ldap)  │  445/tcp(smb)
192.168.1.11     SQL27       ✓    Windows, MSSQL        1433/tcp(mssql)  │  3389/tcp(rdp)
```

Pwned host hostnames are shown in **red** in the terminal. Use `net-scan edit --host <IP> --pwned` to mark a host as pwned, and `--pwned=false` to clear it.

**Flags:**
```
-H, --host       Filter by IP (prefix match)
-p, --port       Filter by port number
-s, --service    Filter by service name (partial match)
    --project    Filter by project
    --json       JSON output
-m, --markdown   Markdown table output
```

---

### `edit` — Edit host or port metadata

Use `edit` to update stored database values without re-running a scan.

```bash
# Add or change a hostname and a manual tag
net-scan edit --host 10.10.10.10 --hostname DC01 --tag Prod

# Update host metadata
net-scan edit --host 10.10.10.10 --project corp --os-guess "Windows Server 2022"

# Update a specific stored port entry
net-scan edit --host 10.10.10.10 --port 445 --service smb --version "Windows SMB" --port-source manual
```

**Flags:**
```
    --host          Exact host IP to edit (required)
-p, --port          Port number for port-level edits
    --protocol      Port protocol for port-level edits (default: tcp)
    --hostname      Set or clear hostname
    --tag           Set or clear a manual host tag (comma-separated allowed)
    --pwned         Set host pwned status (--pwned or --pwned=false)
    --os-guess      Set or clear OS guess
    --project       Set or clear project
    --host-source   Set or clear host source
    --service       Set or clear port service
    --version       Set or clear port version
    --state         Set or clear port state
    --port-source   Set or clear port source
```

Manual tags are additive and are shown together with the auto-derived tags in `net-scan list`.

---

### `export` — Export for other tools

```bash
# Get all MSSQL targets → feed into credops
net-scan export --service mssql --format targets-file > mssql_targets.txt
credops creds test -t mssql_targets.txt -P mssql

# All hosts with SMB open for nxc
net-scan export --port 445 --format nxc-list

# Filter by project
net-scan export --project corp-internal --format targets-file
```

**Formats:**
| Format | Output |
|--------|--------|
| `targets-file` / `credops-targets` | One `IP:PORT` per line |
| `nxc-list` | Space-separated unique IPs |

**Flags:**
```
    --format     targets-file | nxc-list | credops-targets (default: targets-file)
-p, --port       Filter by port
-s, --service    Filter by service
    --project    Filter by project
```

---

## Project Structure

```
net-scan/
├── cmd/net-scan/main.go
├── internal/
│   ├── cli/          # cobra commands (root, scan, ingest, list, edit, export)
│   ├── db/           # SQLite init, schema, upsert/query operations
│   ├── models/       # Host, OpenPort structs
│   ├── parser/       # nmap XML + SharpScan parsers
│   └── runner/       # nmap executor (streaming, sudo, proxychains)
├── Makefile
├── go.mod
└── README.md
```

**Makefile targets:** `make build` (default), `make clean`

---

## Integration

| Consumer | Usage |
|----------|-------|
| `credops` | Reads `~/.pwnbox/network.db` to scope tests to open ports |
| `pwnbox-tools` | Calls `net-scan scan` as subprocess |
| Manual | `net-scan export --service mssql \| credops ...` |
