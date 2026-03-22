package cli

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	dbpkg "github.com/pwnbox/net_scan/internal/db"
	"github.com/pwnbox/net_scan/internal/models"
	"github.com/spf13/cobra"
)

var (
	addIP      string
	addFile    string
	addProject string
)

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add one or more hosts to the database",
	Long: `Seed the database with known IPs before scanning.
Subsequent scans will enrich these entries with open ports, services, and version info.

Examples:
  net-scan add --ip 10.0.0.5
  net-scan add --file scope.txt
  net-scan add --file scope.txt --project corp-internal`,
	PreRunE: openDB,
	RunE:    runAdd,
}

func init() {
	addCmd.Flags().StringVarP(&addIP, "ip", "i", "", "Single IP address to add")
	addCmd.Flags().StringVarP(&addFile, "file", "f", "", "File containing one IP per line")
	addCmd.Flags().StringVar(&addProject, "project", "", "Project label to assign to hosts")
	rootCmd.AddCommand(addCmd)
}

func runAdd(cmd *cobra.Command, args []string) error {
	if addIP == "" && addFile == "" {
		return fmt.Errorf("provide --ip or --file")
	}

	var ips []string

	if addIP != "" {
		if !isValidIP(addIP) {
			return fmt.Errorf("invalid IP address: %s", addIP)
		}
		ips = append(ips, addIP)
	}

	if addFile != "" {
		fileIPs, err := readIPsFromFile(addFile)
		if err != nil {
			return err
		}
		ips = append(ips, fileIPs...)
	}

	added, skipped := 0, 0
	for _, ip := range ips {
		existed, err := dbpkg.AddHost(gDB, models.Host{
			IP:      ip,
			Source:  "manual",
			Project: addProject,
		})
		if err != nil {
			return fmt.Errorf("add %s: %w", ip, err)
		}
		if existed {
			fmt.Printf("  %s~%s  %-17s  already exists — updated project/source\n",
				ansiDim, ansiReset, ip)
			skipped++
		} else {
			fmt.Printf("  %s+%s  %-17s  added\n", ansiGreen, ansiReset, ip)
			added++
		}
	}

	fmt.Printf("\n  %s%d added  ·  %d already existed%s\n\n",
		ansiDim, added, skipped, ansiReset)
	return nil
}

func readIPsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file %s: %w", path, err)
	}
	defer f.Close()

	var ips []string
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !isValidIP(line) {
			return nil, fmt.Errorf("%s:%d: invalid IP address: %q", path, lineNum, line)
		}
		ips = append(ips, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read file %s: %w", path, err)
	}
	return ips, nil
}

func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}
