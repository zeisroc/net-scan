// Package netscan exposes net-scan workflows for orchestration by pwnctrl.
package netscan

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

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
