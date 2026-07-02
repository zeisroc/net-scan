package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	dbpkg "github.com/pwnbox/net_scan/internal/db"
	"github.com/spf13/cobra"
)

var (
	exportFormat       string
	exportPort         string
	exportService      string
	exportProject      string
	exportPrintSources bool
	exportMerge        bool
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export hosts/ports for other tools",
	Long: `Export filtered results in formats consumable by credops, nxc, or other tools.

Formats:
  targets-file      (alias: credops-targets)  — one IP:PORT per line
  nxc-list                                    — space-separated IPs

Example:
  net-scan export --service mssql --format targets-file > mssql.txt
  credops creds test -t mssql.txt -P mssql`,
	PreRunE: openDB,
	RunE:    runExport,
}

func init() {
	exportCmd.Flags().StringVar(&exportFormat, "format", "targets-file",
		"Output format: targets-file, nxc-list, credops-targets")
	exportCmd.Flags().StringVarP(&exportPort, "port", "p", "", "Filter by port number(s): 445 or 445,3389,5985")
	exportCmd.Flags().StringVarP(&exportService, "service", "s", "", "Filter by service name")
	exportCmd.Flags().StringVar(&exportProject, "project", "", "Filter by project label")
	exportCmd.Flags().BoolVar(&exportPrintSources, "print-sources", false, "Append source asset(s) to each exported line")
	exportCmd.Flags().BoolVar(&exportMerge, "merge", false, "Merge ports per host into one line: IP:22,80,443")
	rootCmd.AddCommand(exportCmd)
}

func runExport(cmd *cobra.Command, args []string) error {
	ports, err := parsePortList(exportPort)
	if err != nil {
		return err
	}

	if exportFormat == "nxc-list" && (exportPrintSources || exportMerge) {
		return fmt.Errorf("--print-sources and --merge are only supported with targets-file/credops-targets")
	}

	rows, err := dbpkg.ListPorts(gDB, dbpkg.PortFilter{
		Ports:   ports,
		Service: exportService,
		Project: exportProject,
	})
	if err != nil {
		return err
	}

	switch exportFormat {
	case "targets-file", "credops-targets":
		switch {
		case exportPrintSources:
			printSourceGroupedTargets(rows, exportMerge)
		case exportMerge:
			printMergedTargets(rows)
		default:
			for _, r := range rows {
				fmt.Printf("%s:%d\n", r.IP, r.Port)
			}
		}
	case "nxc-list":
		seen := map[string]struct{}{}
		var ips []string
		for _, r := range rows {
			if _, ok := seen[r.IP]; !ok {
				seen[r.IP] = struct{}{}
				ips = append(ips, r.IP)
			}
		}
		fmt.Println(strings.Join(ips, " "))
	default:
		return fmt.Errorf("unknown format %q; use: targets-file, nxc-list, credops-targets", exportFormat)
	}

	return nil
}

func parsePortList(raw string) ([]int, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	seen := make(map[int]struct{}, len(parts))
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token == "" {
			return nil, fmt.Errorf("invalid --port value %q", raw)
		}
		port, err := strconv.Atoi(token)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q in --port list", token)
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

func printMergedTargets(rows []dbpkg.ListRow) {
	hostPorts := make(map[string]map[int]struct{})
	for _, r := range rows {
		if _, ok := hostPorts[r.IP]; !ok {
			hostPorts[r.IP] = map[int]struct{}{}
		}
		hostPorts[r.IP][r.Port] = struct{}{}
	}

	ips := make([]string, 0, len(hostPorts))
	for ip := range hostPorts {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	for _, ip := range ips {
		fmt.Printf("%s:%s\n", ip, joinPorts(hostPorts[ip]))
	}
}

// printSourceGroupedTargets prints one "# Source" block per distinct source,
// listing every IP:PORT that came from that source (sorted by IP). When merge
// is true, all ports for a given IP within a source are combined onto a
// single "IP:port,port,port" line instead of one line per port.
func printSourceGroupedTargets(rows []dbpkg.ListRow, merge bool) {
	const unspecified = "unspecified"

	// source -> IP -> set of ports
	grouped := make(map[string]map[string]map[int]struct{})
	for _, r := range rows {
		sources := splitSources(r.Source)
		if len(sources) == 0 {
			sources = []string{unspecified}
		}
		for _, src := range sources {
			ips, ok := grouped[src]
			if !ok {
				ips = make(map[string]map[int]struct{})
				grouped[src] = ips
			}
			if _, ok := ips[r.IP]; !ok {
				ips[r.IP] = map[int]struct{}{}
			}
			ips[r.IP][r.Port] = struct{}{}
		}
	}

	sources := make([]string, 0, len(grouped))
	for src := range grouped {
		sources = append(sources, src)
	}
	sort.Strings(sources)

	for i, src := range sources {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("# %s\n", src)

		ips := make([]string, 0, len(grouped[src]))
		for ip := range grouped[src] {
			ips = append(ips, ip)
		}
		sort.Strings(ips)

		for _, ip := range ips {
			if merge {
				fmt.Printf("%s:%s\n", ip, joinPorts(grouped[src][ip]))
				continue
			}
			ports := make([]int, 0, len(grouped[src][ip]))
			for port := range grouped[src][ip] {
				ports = append(ports, port)
			}
			sort.Ints(ports)
			for _, port := range ports {
				fmt.Printf("%s:%d\n", ip, port)
			}
		}
	}
}

func splitSources(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		src := strings.TrimSpace(part)
		if src == "" {
			continue
		}
		if _, ok := seen[src]; ok {
			continue
		}
		seen[src] = struct{}{}
		out = append(out, src)
	}
	sort.Strings(out)
	return out
}

func joinPorts(portSet map[int]struct{}) string {
	ports := make([]int, 0, len(portSet))
	for port := range portSet {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port))
	}
	return strings.Join(parts, ",")
}
