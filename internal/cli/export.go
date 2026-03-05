package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	dbpkg "github.com/pwnbox/net_scan/internal/db"
)

var (
	exportFormat  string
	exportPort    int
	exportService string
	exportProject string
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
	exportCmd.Flags().IntVarP(&exportPort, "port", "p", 0, "Filter by port number")
	exportCmd.Flags().StringVarP(&exportService, "service", "s", "", "Filter by service name")
	exportCmd.Flags().StringVar(&exportProject, "project", "", "Filter by project label")
	rootCmd.AddCommand(exportCmd)
}

func runExport(cmd *cobra.Command, args []string) error {
	rows, err := dbpkg.ListPorts(gDB, dbpkg.PortFilter{
		Port:    exportPort,
		Service: exportService,
		Project: exportProject,
	})
	if err != nil {
		return err
	}

	switch exportFormat {
	case "targets-file", "credops-targets":
		for _, r := range rows {
			fmt.Printf("%s:%d\n", r.IP, r.Port)
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
