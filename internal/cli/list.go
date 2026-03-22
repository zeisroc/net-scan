package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	dbpkg "github.com/pwnbox/net_scan/internal/db"
	"github.com/spf13/cobra"
)

var (
	listHost    string
	listPort    int
	listService string
	listProject string
	listDomain  string
	listJSON    bool
	listMD      bool
)

var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "Query the database",
	PreRunE: openDB,
	RunE:    runList,
}

func init() {
	listCmd.Flags().StringVarP(&listHost, "host", "H", "", "Filter by IP (prefix match)")
	listCmd.Flags().IntVarP(&listPort, "port", "p", 0, "Filter by port number")
	listCmd.Flags().StringVarP(&listService, "service", "s", "", "Filter by service name (partial match)")
	listCmd.Flags().StringVar(&listProject, "project", "", "Filter by project label")
	listCmd.Flags().StringVar(&listDomain, "domain", "", `Filter by domain (exact match); use "none" for hosts with no domain`)
	listCmd.Flags().BoolVar(&listJSON, "json", false, "Output as JSON")
	listCmd.Flags().BoolVarP(&listMD, "markdown", "m", false, "Output as markdown table")
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	hosts, err := dbpkg.ListHosts(gDB, dbpkg.PortFilter{
		IP:      listHost,
		Port:    listPort,
		Service: listService,
		Project: listProject,
		Domain:  listDomain,
	})
	if err != nil {
		return err
	}

	if len(hosts) == 0 {
		fmt.Println("[i] No results.")
		return nil
	}

	switch {
	case listJSON:
		return printHostsJSON(hosts)
	case listMD:
		printHostsMarkdown(hosts)
	default:
		printHostsTable(hosts)
	}
	return nil
}

// ── ANSI constants ────────────────────────────────────────────────────────────

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// padRight pads plain (no ANSI) text to the given visible width.
// Uses rune count so multi-byte UTF-8 characters (e.g. "—", "✓") align correctly.
// Always call this on the raw string BEFORE wrapping in color codes.
func padRight(s string, width int) string {
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

// runeLen returns the visible rune count of a plain string.
func runeLen(s string) int {
	return utf8.RuneCountInString(s)
}

// ── Terminal table ────────────────────────────────────────────────────────────

// listRow holds pre-formatted, plain (ANSI-free) display values for one host.
type listRow struct {
	ip      string
	host    string
	domain  string
	pwnd    string
	tag     string
	ports   string
	isPwned bool
}

func buildListRows(hosts []dbpkg.HostRow) []listRow {
	rows := make([]listRow, len(hosts))
	for i, h := range hosts {
		hostname := h.Hostname
		if hostname == "" {
			hostname = "—"
		}
		domain := h.Domain
		if domain == "" {
			domain = "—"
		}
		tag := h.Tag
		if tag == "" {
			tag = "UNKNOWN"
		}
		pwnd := "-"
		if h.Pwned {
			pwnd = "✓"
		}
		rows[i] = listRow{
			ip:      h.IP,
			host:    hostname,
			domain:  domain,
			pwnd:    pwnd,
			tag:     tag,
			ports:   formatPortsCompact(h.Ports),
			isPwned: h.Pwned,
		}
	}
	return rows
}

// formatPortsCompact builds a compact port list: "80(http)  443(https)  22(ssh)"
// Returns a dim "not scanned" label for hosts with no ports yet.
// This is the plain (ANSI-free) version used for markdown and JSON output.
func formatPortsCompact(ports []dbpkg.PortInfo) string {
	if len(ports) == 0 {
		return "not scanned"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		entry := strconv.Itoa(p.Port)
		if p.Service != "" {
			entry += "(" + p.Service + ")"
		}
		parts = append(parts, entry)
	}
	return strings.Join(parts, "  ")
}

// formatPortsHighlighted returns an ANSI-colored port list where ports in the
// interesting set are bold red and all others are green.
func formatPortsHighlighted(ports []dbpkg.PortInfo, interesting map[int]bool) string {
	if len(ports) == 0 {
		return ansiDim + "not scanned" + ansiReset
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		entry := strconv.Itoa(p.Port)
		if p.Service != "" {
			entry += "(" + p.Service + ")"
		}
		if interesting[p.Port] {
			parts = append(parts, ansiBold+ansiRed+entry+ansiReset)
		} else {
			parts = append(parts, ansiGreen+entry+ansiReset)
		}
	}
	return strings.Join(parts, "  ")
}

func printHostsTable(hosts []dbpkg.HostRow) {
	totalPorts := 0
	for _, h := range hosts {
		totalPorts += len(h.Ports)
	}

	// Build interesting-port set from config (nil-safe).
	interesting := make(map[int]bool)
	if gConfig != nil {
		for _, p := range gConfig.InterestingPorts {
			interesting[p] = true
		}
	}

	rows := buildListRows(hosts)

	// ── Column widths: computed from visible (rune-count) strings ────────────
	wIP, wHost, wDomain, wPwnd, wTag, wPorts :=
		runeLen("IP"), runeLen("HOSTNAME"), runeLen("DOMAIN"), runeLen("PWND"), runeLen("TAGS"), runeLen("PORTS")
	for _, r := range rows {
		if runeLen(r.ip) > wIP {
			wIP = runeLen(r.ip)
		}
		if runeLen(r.host) > wHost {
			wHost = runeLen(r.host)
		}
		if runeLen(r.domain) > wDomain {
			wDomain = runeLen(r.domain)
		}
		if runeLen(r.tag) > wTag {
			wTag = runeLen(r.tag)
		}
		if runeLen(r.ports) > wPorts {
			wPorts = runeLen(r.ports)
		}
	}
	_ = wPorts // last column: no right-padding needed
	_ = wPwnd  // fixed at header width

	// ── Summary ───────────────────────────────────────────────────────────────
	fmt.Printf("\n  %s%d host(s)  ·  %d open port(s)%s\n\n",
		ansiDim, len(hosts), totalPorts, ansiReset)

	// ── Header ────────────────────────────────────────────────────────────────
	fmt.Printf("  %s  %s  %s  %s  %s  %s\n",
		ansiBold+padRight("IP", wIP)+ansiReset,
		ansiBold+padRight("HOSTNAME", wHost)+ansiReset,
		ansiBold+padRight("DOMAIN", wDomain)+ansiReset,
		ansiBold+padRight("PWND", wPwnd)+ansiReset,
		ansiBold+padRight("TAGS", wTag)+ansiReset,
		ansiBold+"PORTS"+ansiReset,
	)

	// ── Separator ─────────────────────────────────────────────────────────────
	fmt.Printf("  %s%s  %s  %s  %s  %s  %s%s\n",
		ansiDim,
		strings.Repeat("─", wIP),
		strings.Repeat("─", wHost),
		strings.Repeat("─", wDomain),
		strings.Repeat("─", wPwnd),
		strings.Repeat("─", wTag),
		strings.Repeat("─", wPorts),
		ansiReset,
	)

	// ── Rows ──────────────────────────────────────────────────────────────────
	for i, r := range rows {
		// IP: always bold cyan
		ipStr := ansiBold + ansiCyan + padRight(r.ip, wIP) + ansiReset

		// Hostname: bold red + pwned marker, or plain
		var hostStr string
		if r.isPwned {
			hostStr = ansiBold + ansiRed + padRight(r.host, wHost) + ansiReset
		} else {
			hostStr = padRight(r.host, wHost)
		}

		// Domain: dim if unknown
		var domainStr string
		if r.domain == "—" {
			domainStr = ansiDim + padRight(r.domain, wDomain) + ansiReset
		} else {
			domainStr = padRight(r.domain, wDomain)
		}

		// PWND: bold red checkmark or dim dash
		var pwndStr string
		if r.isPwned {
			pwndStr = ansiBold + ansiRed + padRight(r.pwnd, wPwnd) + ansiReset
		} else {
			pwndStr = ansiDim + padRight(r.pwnd, wPwnd) + ansiReset
		}

		// Tags: yellow, or dim for UNKNOWN
		var tagStr string
		if r.tag == "UNKNOWN" {
			tagStr = ansiDim + padRight(r.tag, wTag) + ansiReset
		} else {
			tagStr = ansiYellow + padRight(r.tag, wTag) + ansiReset
		}

		// Ports: interesting ports bold red, others green, unscanned dim
		portsStr := formatPortsHighlighted(hosts[i].Ports, interesting)

		fmt.Printf("  %s  %s  %s  %s  %s  %s\n",
			ipStr, hostStr, domainStr, pwndStr, tagStr, portsStr)
	}

	fmt.Println()
}

// ── Markdown ──────────────────────────────────────────────────────────────────

func printHostsMarkdown(hosts []dbpkg.HostRow) {
	fmt.Println("| IP | HOSTNAME | DOMAIN | PWND | TAGS | PORTS |")
	fmt.Println("|---|---|---|---|---|---|")
	for _, h := range hosts {
		hostname := h.Hostname
		if hostname == "" {
			hostname = "—"
		}
		domain := h.Domain
		if domain == "" {
			domain = "—"
		}
		pwnd := "✗"
		if h.Pwned {
			pwnd = "✓"
		}
		tag := h.Tag
		if tag == "" {
			tag = "UNKNOWN"
		}
		fmt.Printf("| %s | %s | %s | %s | %s | %s |\n",
			h.IP, hostname, domain, pwnd, tag, formatPortsCompact(h.Ports))
	}
}

// ── JSON ──────────────────────────────────────────────────────────────────────

func printHostsJSON(hosts []dbpkg.HostRow) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(hosts)
}
