package cli

import (
	"fmt"
	"strings"

	dbpkg "github.com/pwnbox/net_scan/internal/db"
	"github.com/spf13/cobra"
)

var (
	editHost       string
	editPort       int
	editProtocol   string
	editHostname   string
	editTag        string
	editOSGuess    string
	editProject    string
	editHostSource string
	editPwned      bool
	editService    string
	editVersion    string
	editState      string
	editPortSource string
)

var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit host or port metadata in the database",
	Long: `Edit metadata already stored in the database.

Examples:
  net-scan edit --host 10.10.10.10 --hostname DC01 --tag Prod
  net-scan edit --host 10.10.10.10 --port 445 --service smb --version "Windows SMB"
  net-scan edit --host 10.10.10.10 --project corp --os-guess "Windows Server"`,
	PreRunE: openDB,
	RunE:    runEdit,
}

func init() {
	editCmd.Flags().StringVar(&editHost, "host", "", "Exact host IP to edit (required)")
	editCmd.Flags().IntVarP(&editPort, "port", "p", 0, "Port number for port-level edits")
	editCmd.Flags().StringVar(&editProtocol, "protocol", "tcp", "Protocol for port-level edits")

	editCmd.Flags().StringVar(&editHostname, "hostname", "", "Set or clear hostname")
	editCmd.Flags().StringVar(&editTag, "tag", "", "Set or clear a manual host tag (comma-separated allowed)")
	editCmd.Flags().StringVar(&editOSGuess, "os-guess", "", "Set or clear OS guess")
	editCmd.Flags().StringVar(&editProject, "project", "", "Set or clear project")
	editCmd.Flags().StringVar(&editHostSource, "host-source", "", "Set or clear host source")
	editCmd.Flags().BoolVar(&editPwned, "pwned", false, "Set host pwned status (--pwned or --pwned=false)")

	editCmd.Flags().StringVar(&editService, "service", "", "Set or clear port service")
	editCmd.Flags().StringVar(&editVersion, "version", "", "Set or clear port version")
	editCmd.Flags().StringVar(&editState, "state", "", "Set or clear port state")
	editCmd.Flags().StringVar(&editPortSource, "port-source", "", "Set or clear port source")

	_ = editCmd.MarkFlagRequired("host")
	rootCmd.AddCommand(editCmd)
}

func runEdit(cmd *cobra.Command, args []string) error {
	hostUpdate := dbpkg.HostUpdate{}
	portUpdate := dbpkg.PortUpdate{}

	setStringUpdate(cmd, "hostname", editHostname, &hostUpdate.Hostname)
	setStringUpdate(cmd, "tag", editTag, &hostUpdate.ManualTag)
	setStringUpdate(cmd, "os-guess", editOSGuess, &hostUpdate.OSGuess)
	setStringUpdate(cmd, "project", editProject, &hostUpdate.Project)
	setStringUpdate(cmd, "host-source", editHostSource, &hostUpdate.Source)
	if cmd.Flags().Changed("pwned") {
		hostUpdate.Pwned = &editPwned
	}

	setStringUpdate(cmd, "service", editService, &portUpdate.Service)
	setStringUpdate(cmd, "version", editVersion, &portUpdate.Version)
	setStringUpdate(cmd, "state", editState, &portUpdate.State)
	setStringUpdate(cmd, "port-source", editPortSource, &portUpdate.Source)

	if !hostUpdate.HasChanges() && !portUpdate.HasChanges() {
		return fmt.Errorf("no edit fields provided")
	}
	if portUpdate.HasChanges() && editPort <= 0 {
		return fmt.Errorf("--port is required when editing port fields")
	}

	if hostUpdate.HasChanges() {
		if err := dbpkg.UpdateHost(gDB, editHost, hostUpdate); err != nil {
			return err
		}
		fmt.Printf("[+] Updated host %s\n", editHost)
	}

	if portUpdate.HasChanges() {
		proto := strings.ToLower(strings.TrimSpace(editProtocol))
		if err := dbpkg.UpdatePort(gDB, editHost, editPort, proto, portUpdate); err != nil {
			return err
		}
		fmt.Printf("[+] Updated port %s:%d/%s\n", editHost, editPort, proto)
	}

	return nil
}

func setStringUpdate(cmd *cobra.Command, flagName, value string, target **string) {
	if !cmd.Flags().Changed(flagName) {
		return
	}
	*target = &value
}
