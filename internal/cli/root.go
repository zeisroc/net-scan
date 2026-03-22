package cli

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	cfgpkg "github.com/pwnbox/net_scan/internal/config"
	dbpkg "github.com/pwnbox/net_scan/internal/db"
)

var (
	dbPath     string
	configPath string
	debug      bool
	verbose    bool
	gDB        *sql.DB
	gConfig    *cfgpkg.Config
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
	defaultCfg := filepath.Join(home, ".pwnbox", "net-scan.yaml")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", defaultDB, "SQLite DB path")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", defaultCfg, "Config file path (default: ~/.pwnbox/net-scan.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Print nmap commands before executing")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Print full nmap output (default: discovered ports only)")
}

func openDB(cmd *cobra.Command, args []string) error {
	var err error
	gDB, err = dbpkg.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	gConfig, err = cfgpkg.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	return nil
}

// Execute is the entry point called from main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
