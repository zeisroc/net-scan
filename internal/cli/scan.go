package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	dbpkg "github.com/pwnbox/net_scan/internal/db"
	"github.com/pwnbox/net_scan/internal/models"
	"github.com/pwnbox/net_scan/internal/parser"
	"github.com/pwnbox/net_scan/internal/runner"
)

var (
	scanTarget    string
	scanProject   string
	scanPortsOnly bool
	scanProxy     string
	scanOutputDir string
	scanThreads   int
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run nmap against a target",
	Long: `Runs a two-phase nmap scan:
  Phase 1: all-ports discovery  (nmap -p-)
  Phase 2: service/version detection (nmap -sV -sC) on discovered ports

Both phases run under sudo. Use --proxy to route through proxychains.`,
	PreRunE: openDB,
	RunE:    runScan,
}

func init() {
	home, _ := os.UserHomeDir()
	defaultOut := filepath.Join(home, ".pwnbox", "scans")

	scanCmd.Flags().StringVarP(&scanTarget, "target", "t", "", "Target IP, CIDR, or @file (required)")
	scanCmd.Flags().StringVar(&scanProject, "project", "", "Engagement label")
	scanCmd.Flags().BoolVar(&scanPortsOnly, "ports-only", false, "Only run all-ports scan (skip -sV/-sC)")
	scanCmd.Flags().StringVar(&scanProxy, "proxy", "", "SOCKS5 proxy host:port (via proxychains)")
	scanCmd.Flags().StringVar(&scanOutputDir, "output-dir", defaultOut, "Directory for raw nmap XML output")
	scanCmd.Flags().IntVar(&scanThreads, "threads", 5000, "nmap --min-rate value")
	_ = scanCmd.MarkFlagRequired("target")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	r := &runner.NmapRunner{
		OutputDir: scanOutputDir,
		MinRate:   scanThreads,
		Proxy:     scanProxy,
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

	if _, err := dbpkg.UpsertHosts(gDB, hosts2); err != nil {
		return fmt.Errorf("save phase2 results: %w", err)
	}

	printHostsSummary(hosts2)
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
	fmt.Fprintln(w, "IP\tHOSTNAME\tPORT\tPROTO\tSERVICE\tVERSION\tSOURCE")
	fmt.Fprintln(w, "──\t────────\t────\t─────\t───────\t───────\t──────")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			r.IP, dash(r.Hostname), r.Port, r.Protocol,
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
