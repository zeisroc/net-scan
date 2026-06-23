package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	dbpkg "github.com/pwnbox/net_scan/internal/db"
	"github.com/pwnbox/net_scan/internal/parser"
)

var (
	ingestFile       string
	ingestFormat     string
	ingestSourceHost string
	ingestProject    string
	ingestSource     string
)

var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Import scanner output from victim machines",
	Long: `Ingest SharpScan or nmap XML output into the database.

SharpScan format:
  # 192.168.1.5 / WEB05
  192.168.1.10:80,445
  192.168.1.11:22,3389

Format is auto-detected unless --format is specified.`,
	PreRunE: openDB,
	RunE:    runIngest,
}

func init() {
	ingestCmd.Flags().StringVarP(&ingestFile, "file", "f", "", "Input file path (stdin if omitted)")
	ingestCmd.Flags().StringVar(&ingestFormat, "format", "auto", "Input format: auto, sharpscan, nmap-xml")
	ingestCmd.Flags().StringVar(&ingestSourceHost, "source-host", "", "Hostname/IP of the machine that ran the scan")
	ingestCmd.Flags().StringVar(&ingestSource, "source", "", "Source name for this ingestion (defaults to detected hostname or 'manual')")
	ingestCmd.Flags().StringVar(&ingestProject, "project", "", "Engagement label")
	rootCmd.AddCommand(ingestCmd)
}

func runIngest(cmd *cobra.Command, args []string) error {
	var r *os.File
	if ingestFile == "" || ingestFile == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(ingestFile)
		if err != nil {
			return fmt.Errorf("open input file: %w", err)
		}
		defer f.Close()
		r = f
	}

	format := ingestFormat
	if format == "auto" {
		format = detectFormat(ingestFile)
	}

	switch format {
	case "sharpscan":
		return ingestSharpScan(r)
	case "nmap-xml":
		return ingestNmapXML(r)
	default:
		return fmt.Errorf("unknown format %q; use: sharpscan, nmap-xml", format)
	}
}

func ingestSharpScan(f *os.File) error {
	result, err := parser.ParseSharpScan(f)
	if err != nil {
		return err
	}

	// Override source host from flag if provided.
	if ingestSourceHost != "" {
		result.SourceHostname = ingestSourceHost
		result.SourceIP = ingestSourceHost
	}

	source := ingestSource
	if source == "" {
		source = result.SourceHostname
	}
	if source == "" {
		source = result.SourceIP
	}
	if source == "" {
		source = "manual"
	}

	for i := range result.Hosts {
		result.Hosts[i].Source = source
		result.Hosts[i].Project = ingestProject
		for j := range result.Hosts[i].Ports {
			result.Hosts[i].Ports[j].Source = source
		}
	}

	count, err := dbpkg.UpsertHosts(gDB, result.Hosts)
	if err != nil {
		return err
	}
	fmt.Printf("[+] Ingested %d host(s), %d port(s) from SharpScan (source: %s)\n",
		len(result.Hosts), count, source)
	return nil
}

func ingestNmapXML(f *os.File) error {
	source := ingestSource
	if source == "" {
		source = ingestSourceHost
	}
	if source == "" {
		source = "manual"
	}

	hosts, err := parser.ParseNmapXML(f, source)
	if err != nil {
		return err
	}
	for i := range hosts {
		hosts[i].Project = ingestProject
	}

	count, err := dbpkg.UpsertHosts(gDB, hosts)
	if err != nil {
		return err
	}
	fmt.Printf("[+] Ingested %d host(s), %d port(s) from nmap XML (source: %s)\n",
		len(hosts), count, source)
	return nil
}

// detectFormat guesses format from file extension.
func detectFormat(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".xml":
		return "nmap-xml"
	default:
		return "sharpscan"
	}
}
