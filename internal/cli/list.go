package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	dbpkg "github.com/pwnbox/net_scan/internal/db"
	"github.com/spf13/cobra"
)

var (
	listHost    string
	listPort    int
	listService string
	listProject string
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

const (
	ansiRed   = "\033[31m"
	ansiReset = "\033[0m"
)

func printHostsTable(hosts []dbpkg.HostRow) {
	fmt.Printf("\n\033[1m─── Results ────────────────────────────────────────────────\033[0m\n")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tHOSTNAME\tPWND\tTAG\tPORTS")
	fmt.Fprintln(w, "──\t────────\t────\t───\t─────")
	for _, h := range hosts {
		hostname := dash(h.Hostname)
		pwnd := "-"
		if h.Pwned {
			hostname = ansiRed + hostname + ansiReset
			pwnd = "✓"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			h.IP, hostname, pwnd, dash(h.Tag), formatPorts(h.Ports))
	}
	w.Flush()
	fmt.Println()
}

func printHostsMarkdown(hosts []dbpkg.HostRow) {
	fmt.Println("| IP | HOSTNAME | PWND | TAG | PORTS |")
	fmt.Println("|---|---|---|---|---|")
	for _, h := range hosts {
		pwnd := "✗"
		if h.Pwned {
			pwnd = "✓"
		}
		fmt.Printf("| %s | %s | %s | %s | %s |\n",
			h.IP, dash(h.Hostname), pwnd, dash(h.Tag), formatPortsMD(h.Ports))
	}
}

func printHostsJSON(hosts []dbpkg.HostRow) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(hosts)
}

// formatPorts renders port list as a compact inline string for terminal output.
// Example: 80/tcp(http)  │  443/tcp(https)  │  3389/tcp(rdp)
func formatPorts(ports []dbpkg.PortInfo) string {
	if len(ports) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		entry := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		if p.Service != "" {
			entry += "(" + p.Service + ")"
		}
		parts = append(parts, entry)
	}
	return strings.Join(parts, "  │  ")
}

// formatPortsMD renders ports for markdown (no pipes to avoid table breakage).
func formatPortsMD(ports []dbpkg.PortInfo) string {
	if len(ports) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		entry := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		if p.Service != "" {
			entry += "(" + p.Service + ")"
		}
		parts = append(parts, entry)
	}
	return strings.Join(parts, ", ")
}
