package db

import (
	"database/sql"
	"fmt"
	"strings"
)

type HostUpdate struct {
	Hostname  *string
	OSGuess   *string
	Source    *string
	Project   *string
	ManualTag *string
}

func (u HostUpdate) HasChanges() bool {
	return u.Hostname != nil || u.OSGuess != nil || u.Source != nil || u.Project != nil || u.ManualTag != nil
}

type PortUpdate struct {
	Service *string
	Version *string
	State   *string
	Source  *string
}

func (u PortUpdate) HasChanges() bool {
	return u.Service != nil || u.Version != nil || u.State != nil || u.Source != nil
}

func UpdateHost(db *sql.DB, ip string, update HostUpdate) error {
	if !update.HasChanges() {
		return fmt.Errorf("no host changes provided")
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin host update: %w", err)
	}
	defer tx.Rollback()

	var hostID int64
	if err := tx.QueryRow(`SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&hostID); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("host %s not found", ip)
		}
		return fmt.Errorf("lookup host %s: %w", ip, err)
	}

	assignments := make([]string, 0, 5)
	args := make([]any, 0, 6)

	if update.Hostname != nil {
		assignments = append(assignments, "hostname = ?")
		args = append(args, strings.TrimSpace(*update.Hostname))
	}
	if update.OSGuess != nil {
		assignments = append(assignments, "os_guess = ?")
		args = append(args, strings.TrimSpace(*update.OSGuess))
	}
	if update.Source != nil {
		assignments = append(assignments, "source = ?")
		args = append(args, strings.TrimSpace(*update.Source))
	}
	if update.Project != nil {
		assignments = append(assignments, "project = ?")
		args = append(args, strings.TrimSpace(*update.Project))
	}

	if len(assignments) > 0 {
		query := fmt.Sprintf("UPDATE hosts SET %s, updated_at = CURRENT_TIMESTAMP WHERE id = ?", strings.Join(assignments, ", "))
		args = append(args, hostID)
		if _, err := tx.Exec(query, args...); err != nil {
			return fmt.Errorf("update host %s: %w", ip, err)
		}
	}

	if update.ManualTag != nil {
		if _, err := tx.Exec(`
			INSERT INTO host_metadata (host_id, manual_tag, updated_at)
			VALUES (?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT(host_id) DO UPDATE SET
				manual_tag = excluded.manual_tag,
				updated_at = CURRENT_TIMESTAMP
		`, hostID, strings.TrimSpace(*update.ManualTag)); err != nil {
			return fmt.Errorf("update manual tag for %s: %w", ip, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit host update: %w", err)
	}

	return nil
}

func UpdatePort(db *sql.DB, ip string, port int, protocol string, update PortUpdate) error {
	if !update.HasChanges() {
		return fmt.Errorf("no port changes provided")
	}

	hostID, err := GetHostID(db, ip)
	if err != nil {
		return fmt.Errorf("lookup host %s: %w", ip, err)
	}
	if hostID == 0 {
		return fmt.Errorf("host %s not found", ip)
	}

	proto := strings.ToLower(strings.TrimSpace(protocol))
	if proto == "" {
		proto = "tcp"
	}

	var portID int64
	if err := db.QueryRow(
		`SELECT id FROM open_ports WHERE host_id = ? AND port = ? AND protocol = ?`,
		hostID, port, proto,
	).Scan(&portID); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("port %d/%s not found for host %s", port, proto, ip)
		}
		return fmt.Errorf("lookup port %d/%s for %s: %w", port, proto, ip, err)
	}

	assignments := make([]string, 0, 5)
	args := make([]any, 0, 5)

	if update.Service != nil {
		assignments = append(assignments, "service = ?")
		args = append(args, strings.TrimSpace(*update.Service))
	}
	if update.Version != nil {
		assignments = append(assignments, "version = ?")
		args = append(args, strings.TrimSpace(*update.Version))
	}
	if update.State != nil {
		assignments = append(assignments, "state = ?")
		args = append(args, strings.TrimSpace(*update.State))
	}
	if update.Source != nil {
		assignments = append(assignments, "source = ?")
		args = append(args, strings.TrimSpace(*update.Source))
	}

	query := fmt.Sprintf("UPDATE open_ports SET %s, scanned_at = CURRENT_TIMESTAMP WHERE id = ?", strings.Join(assignments, ", "))
	args = append(args, portID)
	if _, err := db.Exec(query, args...); err != nil {
		return fmt.Errorf("update port %d/%s for %s: %w", port, proto, ip, err)
	}

	return nil
}
