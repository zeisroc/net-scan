package cli

import (
	"encoding/json"
	"fmt"
	"os"

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
	rows, err := dbpkg.ListPorts(gDB, dbpkg.PortFilter{
		IP:      listHost,
		Port:    listPort,
		Service: listService,
		Project: listProject,
	})
	if err != nil {
		return err
	}

	if len(rows) == 0 {
		fmt.Println("[i] No results.")
		return nil
	}

	switch {
	case listJSON:
		return printJSON(rows)
	case listMD:
		printMarkdownTable(rows)
	default:
		printRowsSummary(rows)
	}
	return nil
}

// printJSON and printMarkdownTable are list-specific formatters.
func printJSON(rows []dbpkg.ListRow) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}

func printMarkdownTable(rows []dbpkg.ListRow) {
	fmt.Println("| IP | HOSTNAME | TAG | PORT | PROTO | SERVICE | VERSION | SOURCE |")
	fmt.Println("|---|---|---|---|---|---|---|---|")
	for _, r := range rows {
		fmt.Printf("| %s | %s | %s | %d | %s | %s | %s | %s |\n",
			r.IP, dash(r.Hostname), r.Tag, r.Port, r.Protocol,
			dash(r.Service), dash(r.Version), r.Source)
	}
}
