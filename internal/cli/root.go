package cli

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	dbpkg "github.com/pwnbox/net_scan/internal/db"
)

var (
	dbPath string
	gDB    *sql.DB
)

var rootCmd = &cobra.Command{
	Use:   "net-scan",
	Short: "nmap wrapper with persistent SQLite storage",
	Long: `net-scan runs structured nmap scans and stores results in
~/.pwnbox/network.db. It also ingests output from SharpScan and exports
data for credops and nxc.`,
	SilenceUsage: true,
}

func init() {
	home, _ := os.UserHomeDir()
	defaultDB := filepath.Join(home, ".pwnbox", "network.db")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", defaultDB, "SQLite DB path")
}

func openDB(cmd *cobra.Command, args []string) error {
	var err error
	gDB, err = dbpkg.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	return nil
}

// Execute is the entry point called from main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
