package db

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/pwnbox/net_scan/internal/models"
)

// MergeSource appends newSrc to existing comma-separated src string if not already present.
func MergeSource(existing, newSrc string) string {
	if existing == "" {
		return newSrc
	}
	for _, s := range strings.Split(existing, ",") {
		if strings.TrimSpace(s) == newSrc {
			return existing
		}
	}
	return existing + ", " + newSrc
}

// UpsertHost inserts or updates a host record. Returns the host ID.
func UpsertHost(db *sql.DB, h models.Host) (int64, error) {
	// Try to insert; on conflict update non-key fields.
	_, err := db.Exec(`
		INSERT INTO hosts (ip, hostname, os_guess, source, project)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			hostname  = CASE WHEN excluded.hostname  != '' THEN excluded.hostname  ELSE hosts.hostname  END,
			os_guess  = CASE WHEN excluded.os_guess  != '' THEN excluded.os_guess  ELSE hosts.os_guess  END,
			source    = hosts.source, -- merged below
			project   = CASE WHEN excluded.project   != '' THEN excluded.project   ELSE hosts.project   END,
			updated_at = CURRENT_TIMESTAMP
	`, h.IP, h.Hostname, h.OSGuess, h.Source, h.Project)
	if err != nil {
		return 0, fmt.Errorf("upsert host %s: %w", h.IP, err)
	}

	// Fetch the row to get id and current source for merging.
	var id int64
	var currentSource string
	if err := db.QueryRow(`SELECT id, source FROM hosts WHERE ip = ?`, h.IP).Scan(&id, &currentSource); err != nil {
		return 0, fmt.Errorf("fetch host %s: %w", h.IP, err)
	}

	// Merge source string.
	merged := MergeSource(currentSource, h.Source)
	if merged != currentSource {
		if _, err := db.Exec(`UPDATE hosts SET source = ? WHERE id = ?`, merged, id); err != nil {
			return 0, fmt.Errorf("update source %s: %w", h.IP, err)
		}
	}

	return id, nil
}

// UpsertPort inserts or updates an open_ports record.
func UpsertPort(db *sql.DB, hostID int64, p models.OpenPort) error {
	_, err := db.Exec(`
		INSERT INTO open_ports (host_id, port, protocol, state, service, version, source)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host_id, port, protocol) DO UPDATE SET
			state     = excluded.state,
			service   = CASE WHEN excluded.service != '' THEN excluded.service ELSE open_ports.service END,
			version   = CASE WHEN excluded.version != '' THEN excluded.version ELSE open_ports.version END,
			source    = open_ports.source, -- merged below
			scanned_at = CURRENT_TIMESTAMP
	`, hostID, p.Port, p.Protocol, p.State, p.Service, p.Version, p.Source)
	if err != nil {
		return fmt.Errorf("upsert port %d/%s: %w", p.Port, p.Protocol, err)
	}

	// Merge source.
	var currentSource string
	if err := db.QueryRow(
		`SELECT source FROM open_ports WHERE host_id = ? AND port = ? AND protocol = ?`,
		hostID, p.Port, p.Protocol,
	).Scan(&currentSource); err != nil {
		return fmt.Errorf("fetch port source: %w", err)
	}

	merged := MergeSource(currentSource, p.Source)
	if merged != currentSource {
		_, err = db.Exec(
			`UPDATE open_ports SET source = ? WHERE host_id = ? AND port = ? AND protocol = ?`,
			merged, hostID, p.Port, p.Protocol,
		)
		if err != nil {
			return fmt.Errorf("update port source: %w", err)
		}
	}

	return nil
}

// UpsertHosts inserts/updates all hosts and their ports. Returns count of new ports written.
func UpsertHosts(db *sql.DB, hosts []models.Host) (int, error) {
	total := 0
	for _, h := range hosts {
		id, err := UpsertHost(db, h)
		if err != nil {
			return total, err
		}
		for _, p := range h.Ports {
			if err := UpsertPort(db, id, p); err != nil {
				return total, err
			}
			total++
		}
	}
	return total, nil
}

// PortFilter holds query filters for listing ports/hosts.
type PortFilter struct {
	IP      string
	Port    int
	Service string
	Project string
}

// ListRow is a flat result row for display.
type ListRow struct {
	IP       string
	Hostname string
	Port     int
	Protocol string
	Service  string
	Version  string
	Source   string
	Project  string
}

// ListPorts queries open_ports joined with hosts, applying optional filters.
func ListPorts(db *sql.DB, f PortFilter) ([]ListRow, error) {
	query := `
		SELECT h.ip, COALESCE(h.hostname,''), op.port, op.protocol,
		       COALESCE(op.service,''), COALESCE(op.version,''), op.source, COALESCE(h.project,'')
		FROM open_ports op
		JOIN hosts h ON op.host_id = h.id
		WHERE 1=1`
	var args []any

	if f.IP != "" {
		query += ` AND h.ip LIKE ?`
		args = append(args, f.IP+"%")
	}
	if f.Port > 0 {
		query += ` AND op.port = ?`
		args = append(args, f.Port)
	}
	if f.Service != "" {
		query += ` AND op.service LIKE ?`
		args = append(args, "%"+f.Service+"%")
	}
	if f.Project != "" {
		query += ` AND h.project = ?`
		args = append(args, f.Project)
	}
	query += ` ORDER BY h.ip, op.port`

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list ports: %w", err)
	}
	defer rows.Close()

	var results []ListRow
	for rows.Next() {
		var r ListRow
		if err := rows.Scan(&r.IP, &r.Hostname, &r.Port, &r.Protocol,
			&r.Service, &r.Version, &r.Source, &r.Project); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// GetHostID returns the ID of a host by IP, or 0 if not found.
func GetHostID(db *sql.DB, ip string) (int64, error) {
	var id int64
	err := db.QueryRow(`SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}
