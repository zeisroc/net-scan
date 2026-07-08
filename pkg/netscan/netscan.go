// Package netscan exposes net-scan workflows for orchestration by pwnctrl.
package netscan

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/pwnbox/net_scan/internal/config"
	dbpkg "github.com/pwnbox/net_scan/internal/db"
	"github.com/pwnbox/net_scan/internal/models"
	"github.com/pwnbox/net_scan/internal/parser"
	"github.com/pwnbox/net_scan/internal/runner"
)

const defaultProxychainsConf = "/etc/proxychains.conf"

// IngestOptions configures scanner-output ingestion.
type IngestOptions struct {
	DBPath       string
	Project      string
	Format       string
	SourceHost   string
	Source       string
	InputName    string
	Input        io.Reader
	OutputWriter io.Writer
}

// NmapOptions configures the hardcoded nmap scan workflow.
type NmapOptions struct {
	DBPath       string
	ConfigPath   string
	Project      string
	Target       string
	OutputDir    string
	PortsOnly    bool
	Sudo         bool
	Proxychains  string
	Debug        bool
	Verbose      bool
	Threads      int
	OutputWriter io.Writer
}

// EnrichOptions configures Phase 2 enrichment for hosts already present in the
// database but not yet service-enriched.
type EnrichOptions struct {
	DBPath       string
	ConfigPath   string
	Project      string
	OutputDir    string
	All          bool
	Sudo         bool
	Proxychains  string
	Debug        bool
	Verbose      bool
	OutputWriter io.Writer
}

// ListOptions configures scan-result listing.
type ListOptions struct {
	DBPath       string
	ConfigPath   string
	Project      string
	Host         string
	Port         int
	Service      string
	Domain       string
	Source       string
	JSON         bool
	Markdown     bool
	OutputWriter io.Writer
}

// Ingest imports SharpScan or nmap XML output into a net-scan database.
func Ingest(opts IngestOptions) error {
	if opts.Input == nil {
		return fmt.Errorf("input is required")
	}
	db, err := dbpkg.Open(opts.DBPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	format := opts.Format
	if format == "" || format == "auto" {
		format = detectFormat(opts.InputName)
	}

	var hosts []models.Host
	var source string
	switch format {
	case "sharpscan":
		result, err := parser.ParseSharpScan(opts.Input)
		if err != nil {
			return err
		}
		if opts.SourceHost != "" {
			result.SourceHostname = opts.SourceHost
			result.SourceIP = opts.SourceHost
		}
		source = firstNonEmpty(opts.Source, result.SourceHostname, result.SourceIP, "manual")
		hosts = result.Hosts
	case "nmap-xml":
		source = firstNonEmpty(opts.Source, opts.SourceHost, "manual")
		hosts, err = parser.ParseNmapXML(opts.Input, source)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q; use: sharpscan, nmap-xml", format)
	}

	for i := range hosts {
		hosts[i].Project = opts.Project
		if hosts[i].Source == "" {
			hosts[i].Source = source
		}
		for j := range hosts[i].Ports {
			if hosts[i].Ports[j].Source == "" {
				hosts[i].Ports[j].Source = source
			}
		}
	}

	count, err := dbpkg.UpsertHosts(db, hosts)
	if err != nil {
		return err
	}
	out(opts.OutputWriter, "[+] Ingested %d host(s), %d port(s) from %s (source: %s)\n", len(hosts), count, format, source)
	return nil
}

// RunNmap runs net-scan's two-phase nmap workflow and persists results.
func RunNmap(opts NmapOptions) error {
	if strings.TrimSpace(opts.Target) == "" {
		return fmt.Errorf("target is required")
	}

	if opts.Threads <= 0 {
		opts.Threads = 5000
	}
	if opts.OutputDir == "" {
		return fmt.Errorf("output dir is required")
	}

	db, err := dbpkg.Open(opts.DBPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	r := &runner.NmapRunner{
		OutputDir:       opts.OutputDir,
		MinRate:         opts.Threads,
		Sudo:            opts.Sudo,
		ProxychainsConf: opts.Proxychains,
		Debug:           opts.Debug,
		Verbose:         opts.Verbose,
		Phase1Template:  cfg.Scan.Phase1,
		Phase2Template:  cfg.Scan.Phase2,
	}

	out(opts.OutputWriter, "\n[*] Phase 1 - All-ports scan: %s\n\n", opts.Target)
	phase1XML, err := r.RunAllPorts(opts.Target)
	if err != nil {
		return fmt.Errorf("phase 1: %w", err)
	}

	hosts, err := parser.ParseNmapXMLFile(phase1XML, "nmap")
	if err != nil {
		return fmt.Errorf("parse phase1 xml: %w", err)
	}
	applyProject(hosts, opts.Project)
	if _, err := dbpkg.UpsertHosts(db, hosts); err != nil {
		return fmt.Errorf("save phase1 results: %w", err)
	}
	if opts.PortsOnly {
		out(opts.OutputWriter, "[+] Stored phase 1 results for %d host(s)\n", len(hosts))
		return nil
	}

	openPorts := collectOpenPorts(hosts)
	if len(openPorts) == 0 {
		out(opts.OutputWriter, "[!] No open ports found - skipping phase 2.\n")
		return nil
	}

	out(opts.OutputWriter, "\n[*] Phase 2 - Service detection on %d port(s)\n\n", len(openPorts))
	phase2XML, err := r.RunServiceDetection(opts.Target, strings.Join(openPorts, ","))
	if err != nil {
		return fmt.Errorf("phase 2: %w", err)
	}

	hosts2, err := parser.ParseNmapXMLFile(phase2XML, "nmap")
	if err != nil {
		return fmt.Errorf("parse phase2 xml: %w", err)
	}
	applyProject(hosts2, opts.Project)
	filterToKnownPorts(hosts2, buildPortSet(hosts))
	if _, err := dbpkg.UpsertHosts(db, hosts2); err != nil {
		return fmt.Errorf("save phase2 results: %w", err)
	}
	for _, h := range hosts {
		_ = dbpkg.MarkPhase2Done(db, h.IP)
	}
	out(opts.OutputWriter, "[+] Stored scan results for %d host(s)\n", len(hosts2))
	return nil
}

// Enrich runs Phase 2 service/version detection for unenriched project hosts.
func Enrich(opts EnrichOptions) error {
	if opts.OutputDir == "" {
		return fmt.Errorf("output dir is required")
	}
	db, err := dbpkg.Open(opts.DBPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	rows, err := dbpkg.ListUnenrichedTargets(db, opts.Project, opts.All)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		if opts.All {
			out(opts.OutputWriter, "[i] No stored TCP ports found.\n")
		} else {
			out(opts.OutputWriter, "[i] No unenriched hosts found.\n")
		}
		return nil
	}

	r := &runner.NmapRunner{
		OutputDir:       opts.OutputDir,
		Sudo:            opts.Sudo,
		ProxychainsConf: opts.Proxychains,
		Debug:           opts.Debug,
		Verbose:         opts.Verbose,
		Phase2Template:  cfg.Scan.Phase2,
	}

	hosts := groupVersionTargets(rows)
	if len(hosts) == 0 {
		out(opts.OutputWriter, "[i] No valid stored ports found.\n")
		return nil
	}

	var enriched []models.Host
	var failures []string
	for _, host := range hosts {
		portList := strings.Join(intSliceToStrings(host.TCPPorts), ",")
		out(opts.OutputWriter, "\n[*] Enrich - %s (%d tcp port(s))\n\n", host.IP, len(host.TCPPorts))
		xmlPath, err := r.RunServiceDetection(host.IP, portList)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", host.IP, err))
			continue
		}

		parsed, err := parser.ParseNmapXMLFile(xmlPath, "nmap")
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: parse xml: %v", host.IP, err))
			continue
		}
		filterToKnownPorts(parsed, host.portSet())
		applyProject(parsed, host.Project)
		if _, err := dbpkg.UpsertHosts(db, parsed); err != nil {
			failures = append(failures, fmt.Sprintf("%s: save results: %v", host.IP, err))
			continue
		}
		_ = dbpkg.MarkPhase2Done(db, host.IP)
		enriched = append(enriched, parsed...)
	}

	if len(failures) > 0 {
		return fmt.Errorf("enrich failed for %d host(s): %s", len(failures), strings.Join(failures, "; "))
	}
	out(opts.OutputWriter, "[+] Enriched %d host(s)\n", len(enriched))
	return nil
}

// List renders scan results using net-scan's grouped host view.
func List(opts ListOptions) error {
	db, err := dbpkg.Open(opts.DBPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	if opts.Source == "LIST" {
		sources, err := dbpkg.ListSources(db)
		if err != nil {
			return err
		}
		if len(sources) == 0 {
			out(opts.OutputWriter, "[i] No sources found.\n")
			return nil
		}
		out(opts.OutputWriter, "[i] Available sources:\n")
		for _, source := range sources {
			out(opts.OutputWriter, "  - %s\n", source)
		}
		out(opts.OutputWriter, "\n")
		return nil
	}

	hosts, err := dbpkg.ListHosts(db, dbpkg.PortFilter{
		IP:      opts.Host,
		Port:    opts.Port,
		Service: opts.Service,
		Project: opts.Project,
		Domain:  opts.Domain,
		Source:  opts.Source,
	})
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		out(opts.OutputWriter, "[i] No results.\n")
		return nil
	}

	switch {
	case opts.JSON:
		enc := json.NewEncoder(opts.OutputWriter)
		enc.SetIndent("", "  ")
		return enc.Encode(hosts)
	case opts.Markdown:
		printHostsMarkdown(opts.OutputWriter, hosts)
	default:
		cfg, err := config.Load(opts.ConfigPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		printHostsTable(opts.OutputWriter, hosts, cfg.InterestingPorts)
	}
	return nil
}

func detectFormat(path string) string {
	if strings.ToLower(filepath.Ext(path)) == ".xml" {
		return "nmap-xml"
	}
	return "sharpscan"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func out(w io.Writer, format string, args ...any) {
	if w != nil {
		_, _ = fmt.Fprintf(w, format, args...)
	}
}

func applyProject(hosts []models.Host, project string) {
	if project == "" {
		return
	}
	for i := range hosts {
		hosts[i].Project = project
	}
}

func collectOpenPorts(hosts []models.Host) []string {
	seen := map[string]struct{}{}
	for _, h := range hosts {
		for _, p := range h.Ports {
			seen[fmt.Sprintf("%d", p.Port)] = struct{}{}
		}
	}
	ports := make([]string, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	return ports
}

func buildPortSet(hosts []models.Host) map[string]struct{} {
	set := map[string]struct{}{}
	for _, h := range hosts {
		for _, p := range h.Ports {
			set[portKey(h.IP, p.Protocol, p.Port)] = struct{}{}
		}
	}
	return set
}

func filterToKnownPorts(hosts []models.Host, known map[string]struct{}) {
	for i := range hosts {
		filtered := make([]models.OpenPort, 0, len(hosts[i].Ports))
		for _, p := range hosts[i].Ports {
			if _, ok := known[portKey(hosts[i].IP, p.Protocol, p.Port)]; ok {
				filtered = append(filtered, p)
			}
		}
		hosts[i].Ports = filtered
	}
}

func portKey(ip, protocol string, port int) string {
	proto := strings.ToLower(strings.TrimSpace(protocol))
	if proto == "" {
		proto = "tcp"
	}
	return fmt.Sprintf("%s|%s|%d", ip, proto, port)
}

type versionTargetHost struct {
	IP       string
	Hostname string
	Project  string
	TCPPorts []int
}

func groupVersionTargets(rows []dbpkg.VersionTargetRow) []versionTargetHost {
	order := make([]string, 0)
	grouped := map[string]*versionTargetHost{}
	for _, row := range rows {
		if row.IP == "" || row.Port <= 0 {
			continue
		}
		host, ok := grouped[row.IP]
		if !ok {
			host = &versionTargetHost{
				IP:       row.IP,
				Hostname: row.Hostname,
				Project:  row.Project,
			}
			grouped[row.IP] = host
			order = append(order, row.IP)
		}
		if strings.ToLower(row.Protocol) == "tcp" || row.Protocol == "" {
			host.TCPPorts = append(host.TCPPorts, row.Port)
		}
	}

	hosts := make([]versionTargetHost, 0, len(order))
	for _, ip := range order {
		host := grouped[ip]
		host.TCPPorts = uniqueSortedInts(host.TCPPorts)
		if len(host.TCPPorts) > 0 {
			hosts = append(hosts, *host)
		}
	}
	return hosts
}

func (h versionTargetHost) portSet() map[string]struct{} {
	set := make(map[string]struct{}, len(h.TCPPorts))
	for _, port := range h.TCPPorts {
		set[portKey(h.IP, "tcp", port)] = struct{}{}
	}
	return set
}

func uniqueSortedInts(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	seen := map[int]struct{}{}
	out := make([]int, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}

func intSliceToStrings(values []int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = fmt.Sprintf("%d", value)
	}
	return out
}

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

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
		rows[i] = listRow{
			ip:      h.IP,
			host:    defaultString(h.Hostname, "—"),
			domain:  defaultString(h.Domain, "—"),
			pwnd:    pwnedLabel(h.Pwned),
			tag:     defaultString(h.Tag, "UNKNOWN"),
			ports:   formatPortsCompact(h.Ports),
			isPwned: h.Pwned,
		}
	}
	return rows
}

func printHostsTable(w io.Writer, hosts []dbpkg.HostRow, interestingPorts []int) {
	totalPorts := 0
	for _, h := range hosts {
		totalPorts += len(h.Ports)
	}

	interesting := make(map[int]bool)
	for _, p := range interestingPorts {
		interesting[p] = true
	}

	rows := buildListRows(hosts)
	wIP, wHost, wDomain, wPwnd, wTag, wPorts :=
		runeLen("IP"), runeLen("HOSTNAME"), runeLen("DOMAIN"), runeLen("PWND"), runeLen("TAGS"), runeLen("PORTS")
	for _, r := range rows {
		wIP = max(wIP, runeLen(r.ip))
		wHost = max(wHost, runeLen(r.host))
		wDomain = max(wDomain, runeLen(r.domain))
		wTag = max(wTag, runeLen(r.tag))
		wPorts = max(wPorts, runeLen(r.ports))
	}

	out(w, "\n  %s%d host(s)  ·  %d open port(s)%s\n\n", ansiDim, len(hosts), totalPorts, ansiReset)
	out(w, "  %s  %s  %s  %s  %s  %s\n",
		ansiBold+padRight("IP", wIP)+ansiReset,
		ansiBold+padRight("HOSTNAME", wHost)+ansiReset,
		ansiBold+padRight("DOMAIN", wDomain)+ansiReset,
		ansiBold+padRight("PWND", wPwnd)+ansiReset,
		ansiBold+padRight("TAGS", wTag)+ansiReset,
		ansiBold+"PORTS"+ansiReset,
	)
	out(w, "  %s%s  %s  %s  %s  %s  %s%s\n",
		ansiDim,
		strings.Repeat("─", wIP),
		strings.Repeat("─", wHost),
		strings.Repeat("─", wDomain),
		strings.Repeat("─", wPwnd),
		strings.Repeat("─", wTag),
		strings.Repeat("─", wPorts),
		ansiReset,
	)

	for i, r := range rows {
		hostStr := padRight(r.host, wHost)
		if r.isPwned {
			hostStr = ansiBold + ansiRed + hostStr + ansiReset
		}

		domainStr := padRight(r.domain, wDomain)
		if r.domain == "—" {
			domainStr = ansiDim + domainStr + ansiReset
		}

		pwndStr := padRight(r.pwnd, wPwnd)
		if r.isPwned {
			pwndStr = ansiBold + ansiRed + pwndStr + ansiReset
		} else {
			pwndStr = ansiDim + pwndStr + ansiReset
		}

		tagStr := padRight(r.tag, wTag)
		if r.tag == "UNKNOWN" {
			tagStr = ansiDim + tagStr + ansiReset
		} else {
			tagStr = ansiYellow + tagStr + ansiReset
		}

		out(w, "  %s  %s  %s  %s  %s  %s\n",
			ansiBold+ansiCyan+padRight(r.ip, wIP)+ansiReset,
			hostStr,
			domainStr,
			pwndStr,
			tagStr,
			formatPortsHighlighted(hosts[i].Ports, interesting),
		)
	}
	out(w, "\n")
}

func printHostsMarkdown(w io.Writer, hosts []dbpkg.HostRow) {
	out(w, "| IP | HOSTNAME | DOMAIN | PWND | TAGS | PORTS |\n")
	out(w, "|---|---|---|---|---|---|\n")
	for _, h := range hosts {
		out(w, "| %s | %s | %s | %s | %s | %s |\n",
			h.IP,
			defaultString(h.Hostname, "—"),
			defaultString(h.Domain, "—"),
			pwnedMarkdownLabel(h.Pwned),
			defaultString(h.Tag, "UNKNOWN"),
			formatPortsCompact(h.Ports),
		)
	}
}

func formatPortsCompact(ports []dbpkg.PortInfo) string {
	if len(ports) == 0 {
		return "not scanned"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		entry := fmt.Sprintf("%d", p.Port)
		if p.Service != "" {
			entry += "(" + p.Service + ")"
		}
		parts = append(parts, entry)
	}
	return strings.Join(parts, "  ")
}

func formatPortsHighlighted(ports []dbpkg.PortInfo, interesting map[int]bool) string {
	if len(ports) == 0 {
		return ansiDim + "not scanned" + ansiReset
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		entry := fmt.Sprintf("%d", p.Port)
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

func padRight(s string, width int) string {
	n := runeLen(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

func runeLen(s string) int {
	return utf8.RuneCountInString(s)
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func pwnedLabel(pwned bool) string {
	if pwned {
		return "✓"
	}
	return "-"
}

func pwnedMarkdownLabel(pwned bool) string {
	if pwned {
		return "✓"
	}
	return "✗"
}
