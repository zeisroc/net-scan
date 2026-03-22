package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	dbpkg "github.com/pwnbox/net_scan/internal/db"
	"github.com/pwnbox/net_scan/internal/models"
	"github.com/pwnbox/net_scan/internal/parser"
	"github.com/pwnbox/net_scan/internal/runner"
	"github.com/spf13/cobra"
)

var (
	scanTarget    string
	scanProject   string
	scanPortsOnly bool
	scanProxy     string
	scanOutputDir string
	scanThreads   int

	enrichProject string
	enrichAll     bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run nmap against a target",
	Long: `Runs a two-phase nmap scan:
  Phase 1: all-ports discovery  (nmap -p-)
  Phase 2: service/version detection (nmap -sV -sC) on discovered ports

Target formats accepted:
  Single IP:            -t 10.10.10.1
  CIDR:                 -t 192.168.1.0/24
  Comma-separated:      -t 10.0.0.1,10.0.0.2,192.168.1.0/24
  File (one per line):  -t /tmp/targets.txt

Both phases run under sudo. Use --proxy to route through proxychains.`,
	PreRunE: openDB,
	RunE:    runScan,
}

var scanVersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Run nmap -sV against stored assets and ports",
	Long: `Runs database-driven version detection against all stored open ports.

This command reads host:port entries from SQLite, groups them per host, and
executes sudo nmap -sV against those exact ports. No discovery phase is run.`,
	PreRunE: openDB,
	RunE:    runScanVersion,
}

var scanEnrichCmd = &cobra.Command{
	Use:   "enrich",
	Short: "Run Phase 2 (-sV -sC) against hosts not yet enriched",
	Long: `Runs Phase 2 service/version detection against hosts ingested without it.

Queries the database for hosts where phase2_done = 0 (e.g. hosts imported
via SharpScan or Phase-1-only scans), groups their TCP ports per host, then
executes sudo nmap -p <ports> -sV -sC per host — identical to the Phase 2
step of a full scan. On success, the host is marked phase2_done = 1.

Use --all to re-run Phase 2 even on hosts already marked as enriched.`,
	PreRunE: openDB,
	RunE:    runScanEnrich,
}

func init() {
	home, _ := os.UserHomeDir()
	defaultOut := filepath.Join(home, ".pwnbox", "scans")

	scanCmd.Flags().StringVarP(&scanTarget, "target", "t", "", "Target: IP, CIDR, comma-separated list, or file path (required)")
	scanCmd.Flags().StringVar(&scanProject, "project", "", "Engagement label")
	scanCmd.Flags().BoolVar(&scanPortsOnly, "ports-only", false, "Only run all-ports scan (skip -sV/-sC)")
	scanCmd.Flags().StringVar(&scanProxy, "proxy", "", "SOCKS5 proxy host:port (via proxychains)")
	scanCmd.Flags().StringVar(&scanOutputDir, "output-dir", defaultOut, "Directory for raw nmap XML output")
	scanCmd.Flags().IntVar(&scanThreads, "threads", 5000, "nmap --min-rate value")
	_ = scanCmd.MarkFlagRequired("target")

	scanVersionCmd.Flags().StringVar(&scanProxy, "proxy", "", "SOCKS5 proxy host:port (via proxychains)")
	scanVersionCmd.Flags().StringVar(&scanOutputDir, "output-dir", defaultOut, "Directory for raw nmap XML output")

	scanEnrichCmd.Flags().StringVar(&scanProxy, "proxy", "", "SOCKS5 proxy host:port (via proxychains)")
	scanEnrichCmd.Flags().StringVar(&scanOutputDir, "output-dir", defaultOut, "Directory for raw nmap XML output")
	scanEnrichCmd.Flags().StringVar(&enrichProject, "project", "", "Only enrich hosts belonging to this project")
	scanEnrichCmd.Flags().BoolVar(&enrichAll, "all", false, "Re-run Phase 2 even on already-enriched hosts")

	scanCmd.AddCommand(scanVersionCmd)
	scanCmd.AddCommand(scanEnrichCmd)
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	r := &runner.NmapRunner{
		OutputDir: scanOutputDir,
		MinRate:   scanThreads,
		Proxy:     scanProxy,
		Debug:     debug,
		Verbose:   verbose,
	}

	target := scanTarget

	fmt.Printf("\n\033[1m[*] Phase 1 — All-ports scan: %s\033[0m\n\n", target)
	phase1XML, err := r.RunAllPorts(target)
	if err != nil {
		return fmt.Errorf("phase 1: %w", err)
	}

	hosts, err := parser.ParseNmapXMLFile(phase1XML, "nmap")
	if err != nil {
		return fmt.Errorf("parse phase1 xml: %w", err)
	}
	applyProject(hosts, scanProject)

	if _, err := dbpkg.UpsertHosts(gDB, hosts); err != nil {
		return fmt.Errorf("save phase1 results: %w", err)
	}

	if scanPortsOnly {
		printHostsSummary(hosts)
		return nil
	}

	openPorts := collectOpenPorts(hosts)
	if len(openPorts) == 0 {
		fmt.Println("[!] No open ports found — skipping phase 2.")
		return nil
	}
	portList := strings.Join(openPorts, ",")

	// Build a set of (ip, port) pairs confirmed in phase 1, so phase 2
	// cannot introduce ports that were not actually discovered.
	phase1Ports := buildPortSet(hosts)

	fmt.Printf("\n\033[1m[*] Phase 2 — Service detection on %d port(s)\033[0m\n\n", len(openPorts))
	phase2XML, err := r.RunServiceDetection(target, portList)
	if err != nil {
		return fmt.Errorf("phase 2: %w", err)
	}

	hosts2, err := parser.ParseNmapXMLFile(phase2XML, "nmap")
	if err != nil {
		return fmt.Errorf("parse phase2 xml: %w", err)
	}
	applyProject(hosts2, scanProject)

	// Filter phase 2 results: only keep ports confirmed by phase 1.
	filterToKnownPorts(hosts2, phase1Ports)

	if _, err := dbpkg.UpsertHosts(gDB, hosts2); err != nil {
		return fmt.Errorf("save phase2 results: %w", err)
	}

	// Mark every host from phase 1 as enriched — phase 2 was run against the
	// full target, covering all hosts discovered in phase 1.
	for _, h := range hosts {
		if err := dbpkg.MarkPhase2Done(gDB, h.IP); err != nil {
			fmt.Printf("[!] Could not mark phase2_done for %s: %v\n", h.IP, err)
		}
	}

	// For Windows hosts where smb-os-discovery did not fire, fall back to
	// a direct nxc SMB probe to retrieve the computer name and domain.
	probeSMBHostnames(hosts2, scanProxy)

	printHostsSummary(hosts2)
	return nil
}

func runScanVersion(cmd *cobra.Command, args []string) error {
	rows, err := dbpkg.ListVersionTargets(gDB)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("[i] No stored open ports found.")
		return nil
	}

	hosts := groupVersionTargets(rows)
	if len(hosts) == 0 {
		fmt.Println("[i] No valid stored ports found.")
		return nil
	}

	r := &runner.NmapRunner{
		OutputDir: scanOutputDir,
		Proxy:     scanProxy,
		Debug:     debug,
		Verbose:   verbose,
	}

	var refreshed []models.Host
	var failures []string

	for _, host := range hosts {
		fmt.Printf("\n\033[1m[*] Version scan — %s (%s)\033[0m\n\n", host.IP, describeVersionTarget(host))

		xmlPath, err := r.RunVersionDetection(host.IP, host.TCPPorts, host.UDPPorts)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", host.IP, err))
			fmt.Printf("[!] Failed to scan %s: %v\n", host.IP, err)
			continue
		}

		parsed, err := parser.ParseNmapXMLFile(xmlPath, "nmap")
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: parse xml: %v", host.IP, err))
			fmt.Printf("[!] Failed to parse results for %s: %v\n", host.IP, err)
			continue
		}

		filterToKnownPorts(parsed, host.portSet())
		applyProject(parsed, host.Project)

		if len(parsed) == 0 {
			fmt.Printf("[i] No open ports reported for %s.\n", host.IP)
			continue
		}

		if _, err := dbpkg.UpsertHosts(gDB, parsed); err != nil {
			failures = append(failures, fmt.Sprintf("%s: save results: %v", host.IP, err))
			fmt.Printf("[!] Failed to save results for %s: %v\n", host.IP, err)
			continue
		}

		refreshed = append(refreshed, parsed...)
	}

	if len(refreshed) > 0 {
		printHostsSummary(refreshed)
	}

	if len(failures) > 0 {
		return fmt.Errorf("version scan failed for %d host(s): %s", len(failures), strings.Join(failures, "; "))
	}

	if len(refreshed) == 0 {
		fmt.Println("[i] No hosts were refreshed.")
	}

	return nil
}

func runScanEnrich(cmd *cobra.Command, args []string) error {
	rows, err := dbpkg.ListUnenrichedTargets(gDB, enrichProject, enrichAll)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		if enrichAll {
			fmt.Println("[i] No stored TCP ports found.")
		} else {
			fmt.Println("[i] No unenriched hosts found. All hosts already have phase2_done = 1.")
			fmt.Println("    Use --all to re-run Phase 2 on all hosts regardless.")
		}
		return nil
	}

	hosts := groupVersionTargets(rows)
	if len(hosts) == 0 {
		fmt.Println("[i] No valid stored ports found.")
		return nil
	}

	r := &runner.NmapRunner{
		OutputDir: scanOutputDir,
		Proxy:     scanProxy,
		Debug:     debug,
		Verbose:   verbose,
	}

	var enriched []models.Host
	var failures []string

	for _, host := range hosts {
		portList := strings.Join(intSliceToStrings(host.TCPPorts), ",")
		fmt.Printf("\n\033[1m[*] Enrich (Phase 2) — %s (%d tcp port(s))\033[0m\n\n", host.IP, len(host.TCPPorts))

		xmlPath, err := r.RunServiceDetection(host.IP, portList)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", host.IP, err))
			fmt.Printf("[!] Failed to scan %s: %v\n", host.IP, err)
			continue
		}

		parsed, err := parser.ParseNmapXMLFile(xmlPath, "nmap")
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: parse xml: %v", host.IP, err))
			fmt.Printf("[!] Failed to parse results for %s: %v\n", host.IP, err)
			continue
		}

		filterToKnownPorts(parsed, host.portSet())
		applyProject(parsed, host.Project)

		if _, err := dbpkg.UpsertHosts(gDB, parsed); err != nil {
			failures = append(failures, fmt.Sprintf("%s: save results: %v", host.IP, err))
			fmt.Printf("[!] Failed to save results for %s: %v\n", host.IP, err)
			continue
		}

		if err := dbpkg.MarkPhase2Done(gDB, host.IP); err != nil {
			fmt.Printf("[!] Could not mark phase2_done for %s: %v\n", host.IP, err)
		}

		// Probe SMB for hostname if 445 was open but smb-os-discovery did not fire.
		// Build a synthetic host entry so probeSMBHostnames can check for 445 and
		// an empty hostname using the same logic as in the main scan pipeline.
		if host.Hostname == "" && containsInt(host.TCPPorts, 445) {
			hostnameFromPhase2 := ""
			for _, ph := range parsed {
				if ph.Hostname != "" {
					hostnameFromPhase2 = ph.Hostname
					break
				}
			}
			if hostnameFromPhase2 == "" {
				probeSMBHostnames([]models.Host{{
					IP:    host.IP,
					Ports: []models.OpenPort{{Port: 445, Protocol: "tcp"}},
				}}, scanProxy)
			}
		}

		enriched = append(enriched, parsed...)
	}

	if len(enriched) > 0 {
		printHostsSummary(enriched)
	}

	if len(failures) > 0 {
		return fmt.Errorf("enrich failed for %d host(s): %s", len(failures), strings.Join(failures, "; "))
	}

	if len(enriched) == 0 {
		fmt.Println("[i] No hosts were enriched.")
	}

	return nil
}

func applyProject(hosts []models.Host, project string) {
	if project == "" {
		return
	}
	for i := range hosts {
		hosts[i].Project = project
	}
}

// collectOpenPorts returns a deduplicated sorted list of port numbers as strings.
func collectOpenPorts(hosts []models.Host) []string {
	seen := map[string]struct{}{}
	for _, h := range hosts {
		for _, p := range h.Ports {
			seen[fmt.Sprintf("%d", p.Port)] = struct{}{}
		}
	}
	var ports []string
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Strings(ports)
	return ports
}

// buildPortSet returns a set of "ip:port" strings from phase 1 results.
func buildPortSet(hosts []models.Host) map[string]struct{} {
	set := map[string]struct{}{}
	for _, h := range hosts {
		for _, p := range h.Ports {
			set[portKey(h.IP, p.Protocol, p.Port)] = struct{}{}
		}
	}
	return set
}

// filterToKnownPorts removes from each host any port not present in the phase1 set,
// preventing phase 2 from introducing false-positive ports.
func filterToKnownPorts(hosts []models.Host, known map[string]struct{}) {
	for i := range hosts {
		var filtered []models.OpenPort
		for _, p := range hosts[i].Ports {
			key := portKey(hosts[i].IP, p.Protocol, p.Port)
			if _, ok := known[key]; ok {
				filtered = append(filtered, p)
			}
		}
		hosts[i].Ports = filtered
	}
}

func printHostsSummary(hosts []models.Host) {
	fmt.Printf("\n\033[1m─── Scan Summary ───────────────────────────────────────────\033[0m\n")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTO\tSERVICE\tVERSION")
	fmt.Fprintln(w, "──\t────\t─────\t───────\t───────")
	for _, h := range hosts {
		for _, p := range h.Ports {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n",
				h.IP, p.Port, p.Protocol, dash(p.Service), dash(p.Version))
		}
	}
	w.Flush()
	fmt.Println()
}

func printRowsSummary(rows []dbpkg.ListRow) {
	fmt.Printf("\n\033[1m─── Results ────────────────────────────────────────────────\033[0m\n")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tHOSTNAME\tTAG\tPORT\tPROTO\tSERVICE\tVERSION\tSOURCE")
	fmt.Fprintln(w, "──\t────────\t───\t────\t─────\t───────\t───────\t──────")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			r.IP, dash(r.Hostname), r.Tag, r.Port, r.Protocol,
			dash(r.Service), dash(r.Version), r.Source)
	}
	w.Flush()
	fmt.Println()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type versionTargetHost struct {
	IP       string
	Hostname string
	Project  string
	TCPPorts []int
	UDPPorts []int
}

func groupVersionTargets(rows []dbpkg.VersionTargetRow) []versionTargetHost {
	order := make([]string, 0)
	grouped := make(map[string]*versionTargetHost)

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

		switch strings.ToLower(row.Protocol) {
		case "", "tcp":
			host.TCPPorts = append(host.TCPPorts, row.Port)
		case "udp":
			host.UDPPorts = append(host.UDPPorts, row.Port)
		}
	}

	hosts := make([]versionTargetHost, 0, len(order))
	for _, ip := range order {
		host := grouped[ip]
		host.TCPPorts = uniqueSortedInts(host.TCPPorts)
		host.UDPPorts = uniqueSortedInts(host.UDPPorts)
		if len(host.TCPPorts) == 0 && len(host.UDPPorts) == 0 {
			continue
		}
		hosts = append(hosts, *host)
	}

	return hosts
}

func uniqueSortedInts(values []int) []int {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[int]struct{}, len(values))
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

func describeVersionTarget(host versionTargetHost) string {
	parts := make([]string, 0, 2)
	if len(host.TCPPorts) > 0 {
		parts = append(parts, fmt.Sprintf("%d tcp port(s)", len(host.TCPPorts)))
	}
	if len(host.UDPPorts) > 0 {
		parts = append(parts, fmt.Sprintf("%d udp port(s)", len(host.UDPPorts)))
	}
	if len(parts) == 0 {
		return "no ports"
	}
	return strings.Join(parts, ", ")
}

func (h versionTargetHost) portSet() map[string]struct{} {
	set := make(map[string]struct{}, len(h.TCPPorts)+len(h.UDPPorts))
	for _, port := range h.TCPPorts {
		set[portKey(h.IP, "tcp", port)] = struct{}{}
	}
	for _, port := range h.UDPPorts {
		set[portKey(h.IP, "udp", port)] = struct{}{}
	}
	return set
}

func portKey(ip, protocol string, port int) string {
	proto := strings.ToLower(strings.TrimSpace(protocol))
	if proto == "" {
		proto = "tcp"
	}
	return ip + "|" + proto + "|" + strconv.Itoa(port)
}

func intSliceToStrings(ints []int) []string {
	out := make([]string, len(ints))
	for i, v := range ints {
		out[i] = strconv.Itoa(v)
	}
	return out
}

// probeSMBHostnames probes hosts that have port 445/tcp open but no hostname
// using nxc (netexec) SMB negotiation — reliable for Windows AD machines even
// when nmap's smb-os-discovery script fails. Updates the DB on success.
// Silently skips if nxc is not installed.
func probeSMBHostnames(hosts []models.Host, proxy string) {
	for _, h := range hosts {
		if h.Hostname != "" {
			continue
		}
		if !hasTCPPort(h, 445) {
			continue
		}

		fmt.Printf("[*] SMB probe — %s\n", h.IP)
		info, err := runner.RunNxcSMB(h.IP, proxy)
		if err != nil {
			fmt.Printf("[!] SMB probe error for %s: %v\n", h.IP, err)
			continue
		}
		if info == nil {
			continue // nxc not installed or no SMB banner
		}

		fmt.Printf("    ✓ %s · %s · %s\n", info.Name, info.Domain, info.OS)

		_, err = dbpkg.UpsertHost(gDB, models.Host{
			IP:       h.IP,
			Hostname: info.Name,
			OSGuess:  info.OS,
			Source:   "nxc",
		})
		if err != nil {
			fmt.Printf("[!] Could not save SMB info for %s: %v\n", h.IP, err)
		}
	}
}

// hasTCPPort reports whether a host has the given port open over TCP.
func hasTCPPort(h models.Host, port int) bool {
	for _, p := range h.Ports {
		if p.Port == port && strings.ToLower(p.Protocol) == "tcp" {
			return true
		}
	}
	return false
}

// containsInt reports whether val is present in the slice.
func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}
