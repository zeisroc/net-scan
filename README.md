# network-scanner

A Go wrapper around `nmap` that runs structured port scans, stores all results in a shared SQLite database (`~/.pwnbox/network.db`), ingests output from [SharpScan](https://github.com/7own/SharpScan) executed on victim machines, and exports data for `credops` and `nxc`.

Part of the **pwnbox** toolchain.

---

## Installation

```bash
go install github.com/pwnbox/net_scan/cmd/network-scanner@latest
```

Or build from source:

```bash
git clone <repo>
cd net_scan
go build -o network-scanner ./cmd/network-scanner/
```

> **Requires:** `nmap` and `sudo` on PATH. `proxychains` only needed when `--proxy` is used.

---

## Database

All results are stored in `~/.pwnbox/network.db` (SQLite). Override with `--db <path>`.

The `credops` tool reads this database directly to scope credential tests to open ports only.

---

## Commands

### `scan` — Run nmap against a target

Two-phase pipeline under `sudo`:

1. **Phase 1** — `nmap -p- --min-rate 5000` — discovers all open ports, printed live as found
2. **Phase 2** — `nmap -sV -sC` on discovered ports — enriches with service/version data

```bash
# Full scan (default)
network-scanner scan -t 10.10.10.1

# Scan a subnet, tag with project label
network-scanner scan -t 192.168.1.0/24 --project corp-internal

# Fast port-only scan (skip service detection)
network-scanner scan -t 10.10.10.1 --ports-only

# Route through proxychains (SOCKS5 pivot)
network-scanner scan -t 172.16.0.0/24 --proxy 127.0.0.1:1080

# Custom rate and output directory
network-scanner scan -t 10.0.0.1 --threads 1000 --output-dir /tmp/scans
```

**Flags:**
```
-t, --target       Target IP, CIDR (required)
    --project      Engagement label
    --ports-only   Skip -sV/-sC phase
    --proxy        SOCKS5 host:port (via proxychains)
    --output-dir   Directory for raw nmap XML (default: ~/.pwnbox/scans/)
    --threads      nmap --min-rate (default: 5000)
```

---

### `ingest` — Import scanner output from victim machines

Import [SharpScan](https://github.com/7own/SharpScan) output or raw nmap XML collected from pivot machines.

```bash
# Ingest SharpScan output (auto-detected)
network-scanner ingest -f sharpscan_output.txt

# Override detected source hostname
network-scanner ingest -f scan.txt --source-host WEB05 --project corp-internal

# Ingest nmap XML
network-scanner ingest -f results.xml --format nmap-xml

# From stdin
cat scan.txt | network-scanner ingest --format sharpscan
```

**SharpScan format:**
```
# 192.168.1.5 / WEB05
192.168.1.10:80,445
192.168.1.11:22,3389
```

The `# ip / hostname` header is parsed automatically as the source identifier.
If a port already exists in the DB from another source, the source field is updated to include both (e.g. `nmap, WEB05`).

**Flags:**
```
-f, --file         Input file (stdin if omitted)
    --format       auto | sharpscan | nmap-xml (default: auto)
    --source-host  Override source hostname
    --project      Engagement label
```

---

### `list` — Query the database

```bash
# List all known hosts and ports
network-scanner list

# Filter by IP prefix
network-scanner list --host 192.168.1

# Filter by service
network-scanner list --service mssql
network-scanner list --service http

# Filter by port
network-scanner list --port 445

# Filter by project
network-scanner list --project corp-internal

# Output as JSON or markdown
network-scanner list --json
network-scanner list --markdown
```

**Example output:**
```
IP               HOSTNAME    PORT   PROTO  SERVICE   VERSION         SOURCE
192.168.1.10     DC01        88     tcp    kerberos  -               nmap, WEB05
192.168.1.10     DC01        389    tcp    ldap      -               nmap
192.168.1.10     DC01        445    tcp    smb       Windows SMB     nmap
192.168.1.11     SQL27       1433   tcp    mssql     MSSQL 2019      WEB05
192.168.1.11     SQL27       3389   tcp    rdp       -               nmap
```

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

### `export` — Export for other tools

```bash
# Get all MSSQL targets → feed into credops
network-scanner export --service mssql --format targets-file > mssql_targets.txt
credops creds test -t mssql_targets.txt -P mssql

# All hosts with SMB open for nxc
network-scanner export --port 445 --format nxc-list

# Filter by project
network-scanner export --project corp-internal --format targets-file
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

## Global Flags

```
--db string   Override SQLite DB path (default: ~/.pwnbox/network.db)
```

---

## Project Structure

```
network-scanner/
├── cmd/network-scanner/main.go
├── internal/
│   ├── cli/          # cobra commands (root, scan, ingest, list, export)
│   ├── db/           # SQLite init, schema, upsert/query operations
│   ├── models/       # Host, OpenPort structs
│   ├── parser/       # nmap XML + SharpScan parsers
│   └── runner/       # nmap executor (streaming, sudo, proxychains)
├── go.mod
└── README.md
```

## Integration

| Consumer | Usage |
|----------|-------|
| `credops` | Reads `~/.pwnbox/network.db` to scope tests to open ports |
| `pwnbox-tools` | Calls `network-scanner scan` as subprocess |
| Manual | `network-scanner export --service mssql \| credops ...` |

