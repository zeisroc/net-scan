package db

import (
	"database/sql"
	"fmt"
	"sort"
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
		INSERT INTO hosts (ip, hostname, os_guess, domain, source, project)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			hostname  = CASE WHEN excluded.hostname  != '' THEN excluded.hostname  ELSE hosts.hostname  END,
			os_guess  = CASE WHEN excluded.os_guess  != '' THEN excluded.os_guess  ELSE hosts.os_guess  END,
			domain    = CASE WHEN excluded.domain    != '' THEN excluded.domain    ELSE hosts.domain    END,
			source    = hosts.source, -- merged below
			project   = CASE WHEN excluded.project   != '' THEN excluded.project   ELSE hosts.project   END,
			updated_at = CURRENT_TIMESTAMP
	`, h.IP, h.Hostname, h.OSGuess, h.Domain, h.Source, h.Project)
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

// AddHost creates a minimal host record (IP + source "manual"). Returns true if the
// row already existed (in which case project is refreshed if provided).
func AddHost(db *sql.DB, h models.Host) (existed bool, err error) {
	// Check if host already exists.
	var existingID int64
	lookupErr := db.QueryRow(`SELECT id FROM hosts WHERE ip = ?`, h.IP).Scan(&existingID)
	existed = lookupErr == nil

	_, err = db.Exec(`
		INSERT INTO hosts (ip, hostname, os_guess, source, project)
		VALUES (?, '', '', ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			source  = hosts.source,  -- merged below
			project = CASE WHEN excluded.project != '' THEN excluded.project ELSE hosts.project END,
			updated_at = CURRENT_TIMESTAMP
	`, h.IP, h.Source, h.Project)
	if err != nil {
		return false, fmt.Errorf("add host %s: %w", h.IP, err)
	}

	// Merge "manual" into source if it wasn't already there.
	var currentSource string
	if err := db.QueryRow(`SELECT source FROM hosts WHERE ip = ?`, h.IP).Scan(&currentSource); err != nil {
		return existed, fmt.Errorf("fetch host %s: %w", h.IP, err)
	}
	merged := MergeSource(currentSource, h.Source)
	if merged != currentSource {
		if _, err := db.Exec(`UPDATE hosts SET source = ? WHERE ip = ?`, merged, h.IP); err != nil {
			return existed, fmt.Errorf("update source %s: %w", h.IP, err)
		}
	}
	return existed, nil
}

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
	Domain  string // exact match; use sentinel value "none" to filter hosts with no domain
	Source  string // exact or partial match on source names (comma-separated in DB)
}

// ListSources returns all distinct source names stored in the database (hosts + open_ports).
func ListSources(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`
		SELECT DISTINCT value FROM (
			SELECT DISTINCT TRIM(value) AS value FROM hosts,
				json_each('["' || REPLACE(COALESCE(source,''), ', ', '","') || '"]')
			WHERE COALESCE(source,'') != ''
			UNION
			SELECT DISTINCT TRIM(value) AS value FROM open_ports op
			JOIN hosts h ON op.host_id = h.id,
				json_each('["' || REPLACE(COALESCE(op.source,''), ', ', '","') || '"]')
			WHERE COALESCE(op.source,'') != ''
		)
		ORDER BY value
	`)
	if err != nil {
		return nil, fmt.Errorf("list sources: %w", err)
	}
	defer rows.Close()

	var sources []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan source: %w", err)
		}
		sources = append(sources, s)
	}
	return sources, rows.Err()
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
	Tag      string
	Project  string
}

// PortInfo holds the display fields for a single open port in grouped results.
type PortInfo struct {
	Port     int
	Protocol string
	Service  string
	Version  string
	Source   string
}

// HostRow is a grouped result containing all matching ports for one host.
type HostRow struct {
	IP       string
	Hostname string
	Domain   string
	Pwned    bool
	Tag      string
	Project  string
	Ports    []PortInfo
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
	if f.Source != "" {
		query += ` AND op.source LIKE ?`
		args = append(args, "%"+f.Source+"%")
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := applyHostTags(db, results); err != nil {
		return nil, err
	}
	return results, nil
}

// ListHosts queries hosts and their ports applying the same filters as ListPorts,
// but returns one HostRow per host with all matching ports grouped together.
func ListHosts(db *sql.DB, f PortFilter) ([]HostRow, error) {
	// Use LEFT JOIN so hosts with no ports (e.g. added via "add" before scanning)
	// still appear. When op.port is NULL the port filter conditions must be skipped.
	query := `
		SELECT h.ip, COALESCE(h.hostname,''),
		       COALESCE(h.domain,''),
		       COALESCE(hm.pwned, 0),
		       op.port, COALESCE(op.protocol,''),
		       COALESCE(op.service,''), COALESCE(op.version,''),
		       COALESCE(op.source,''), COALESCE(h.project,'')
		FROM hosts h
		LEFT JOIN open_ports op ON op.host_id = h.id
		LEFT JOIN host_metadata hm ON hm.host_id = h.id
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
	if f.Domain == "none" {
		query += ` AND COALESCE(h.domain,'') = ''`
	} else if f.Domain != "" {
		query += ` AND h.domain = ?`
		args = append(args, f.Domain)
	}
	if f.Source != "" {
		query += ` AND op.source LIKE ?`
		args = append(args, "%"+f.Source+"%")
	}
	query += ` ORDER BY h.ip, op.port`

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()

	var order []string
	grouped := map[string]*HostRow{}

	for rows.Next() {
		var ip, hostname, domain, protocol, service, version, source, project string
		var pwnedInt int
		var port sql.NullInt64
		if err := rows.Scan(&ip, &hostname, &domain, &pwnedInt, &port, &protocol,
			&service, &version, &source, &project); err != nil {
			return nil, fmt.Errorf("scan host row: %w", err)
		}

		host, ok := grouped[ip]
		if !ok {
			host = &HostRow{
				IP:       ip,
				Hostname: hostname,
				Domain:   domain,
				Pwned:    pwnedInt != 0,
				Project:  project,
			}
			grouped[ip] = host
			order = append(order, ip)
		}
		// port is NULL for hosts that have no open_ports rows yet.
		if port.Valid {
			host.Ports = append(host.Ports, PortInfo{
				Port:     int(port.Int64),
				Protocol: protocol,
				Service:  service,
				Version:  version,
				Source:   source,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := make([]HostRow, 0, len(order))
	for _, ip := range order {
		result = append(result, *grouped[ip])
	}

	if err := applyTagsToHostRows(db, result); err != nil {
		return nil, err
	}
	return result, nil
}

// VersionTargetRow is a stored open port used to drive DB-backed version scans.
type VersionTargetRow struct {
	IP       string
	Hostname string
	Port     int
	Protocol string
	Project  string
}

// ListVersionTargets returns all stored open ports ordered for host-by-host scans.
func ListVersionTargets(db *sql.DB) ([]VersionTargetRow, error) {
	rows, err := db.Query(`
		SELECT h.ip,
		       COALESCE(h.hostname, ''),
		       op.port,
		       LOWER(op.protocol),
		       COALESCE(h.project, '')
		FROM open_ports op
		JOIN hosts h ON op.host_id = h.id
		WHERE op.state = 'open'
		ORDER BY h.ip, op.protocol, op.port
	`)
	if err != nil {
		return nil, fmt.Errorf("list version targets: %w", err)
	}
	defer rows.Close()

	var results []VersionTargetRow
	for rows.Next() {
		var r VersionTargetRow
		if err := rows.Scan(&r.IP, &r.Hostname, &r.Port, &r.Protocol, &r.Project); err != nil {
			return nil, fmt.Errorf("scan version target row: %w", err)
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

// ListUnenrichedTargets returns stored open TCP ports for hosts that have not yet had
// Phase 2 (service/version detection) run against them.
// When all is true, all hosts are returned regardless of phase2_done status.
// When project is non-empty, only hosts belonging to that project are included.
func ListUnenrichedTargets(db *sql.DB, project string, all bool) ([]VersionTargetRow, error) {
	query := `
		SELECT h.ip,
		       COALESCE(h.hostname, ''),
		       op.port,
		       LOWER(op.protocol),
		       COALESCE(h.project, '')
		FROM open_ports op
		JOIN hosts h ON op.host_id = h.id
		WHERE op.state = 'open'
		AND LOWER(op.protocol) = 'tcp'`
	var args []any
	if !all {
		query += ` AND h.phase2_done = 0`
	}
	if project != "" {
		query += ` AND h.project = ?`
		args = append(args, project)
	}
	query += ` ORDER BY h.ip, op.port`

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list unenriched targets: %w", err)
	}
	defer rows.Close()

	var results []VersionTargetRow
	for rows.Next() {
		var r VersionTargetRow
		if err := rows.Scan(&r.IP, &r.Hostname, &r.Port, &r.Protocol, &r.Project); err != nil {
			return nil, fmt.Errorf("scan unenriched target row: %w", err)
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// MarkPhase2Done records that Phase 2 (service/version detection) has been
// completed for the given host IP.
func MarkPhase2Done(db *sql.DB, ip string) error {
	_, err := db.Exec(
		`UPDATE hosts SET phase2_done = 1, updated_at = CURRENT_TIMESTAMP WHERE ip = ?`, ip,
	)
	if err != nil {
		return fmt.Errorf("mark phase2 done %s: %w", ip, err)
	}
	return nil
}

type hostFingerprint struct {
	ports     map[int]struct{}
	services  []string
	manualTag string
}

// buildFingerprints loads all open ports and manual tags for the given host IPs
// and returns a per-host fingerprint used for tag classification.
func buildFingerprints(db *sql.DB, ips []string) (map[string]*hostFingerprint, error) {
	if len(ips) == 0 {
		return map[string]*hostFingerprint{}, nil
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ips)), ",")
	args := make([]any, 0, len(ips))
	for _, ip := range ips {
		args = append(args, ip)
	}

	query := fmt.Sprintf(`
		SELECT h.ip, op.port, LOWER(COALESCE(op.service, '')), COALESCE(hm.manual_tag, '')
		FROM open_ports op
		JOIN hosts h ON op.host_id = h.id
		LEFT JOIN host_metadata hm ON hm.host_id = h.id
		WHERE op.state = 'open' AND h.ip IN (%s)
	`, placeholders)

	tagRows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("load host tags: %w", err)
	}
	defer tagRows.Close()

	fingerprints := make(map[string]*hostFingerprint, len(ips))
	for tagRows.Next() {
		var ip string
		var port int
		var service, manualTag string
		if err := tagRows.Scan(&ip, &port, &service, &manualTag); err != nil {
			return nil, fmt.Errorf("scan host tag row: %w", err)
		}

		fp, ok := fingerprints[ip]
		if !ok {
			fp = &hostFingerprint{ports: map[int]struct{}{}}
			fingerprints[ip] = fp
		}
		if port > 0 {
			fp.ports[port] = struct{}{}
		}
		if service != "" {
			fp.services = append(fp.services, service)
		}
		if manualTag != "" {
			fp.manualTag = manualTag
		}
	}
	if err := tagRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate host tag rows: %w", err)
	}

	return fingerprints, nil
}

func applyHostTags(db *sql.DB, rows []ListRow) error {
	if len(rows) == 0 {
		return nil
	}

	ips := distinctSortedIPs(rows)
	fingerprints, err := buildFingerprints(db, ips)
	if err != nil {
		return err
	}

	for i := range rows {
		rows[i].Tag = classifyTags(fingerprints[rows[i].IP])
	}

	return nil
}

func applyTagsToHostRows(db *sql.DB, rows []HostRow) error {
	if len(rows) == 0 {
		return nil
	}

	ips := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.IP != "" {
			ips = append(ips, r.IP)
		}
	}

	fingerprints, err := buildFingerprints(db, ips)
	if err != nil {
		return err
	}

	for i := range rows {
		rows[i].Tag = classifyTags(fingerprints[rows[i].IP])
	}

	return nil
}

func distinctSortedIPs(rows []ListRow) []string {
	seen := make(map[string]struct{}, len(rows))
	ips := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.IP == "" {
			continue
		}
		if _, ok := seen[row.IP]; ok {
			continue
		}
		seen[row.IP] = struct{}{}
		ips = append(ips, row.IP)
	}
	sort.Strings(ips)
	return ips
}

func classifyTags(fp *hostFingerprint) string {
	if fp == nil {
		return "UNKNOWN"
	}

	var tags []string
	for _, manualTag := range splitTagValues(fp.manualTag) {
		tags = appendUniqueTags(tags, manualTag)
	}

	if hasAllPorts(fp, 88, 389) {
		tags = appendUniqueTags(tags, "DC")
	}
	if hasAnyPort(fp, 3389, 5985, 5986, 445, 135, 139) ||
		hasAnyService(fp, "microsoft-ds", "msrpc", "ms-wbt-server", "winrm", "smb") {
		tags = appendUniqueTags(tags, "Windows")
	}
	if hasAnyPort(fp, 22) || hasAnyService(fp, "ssh") {
		tags = appendUniqueTags(tags, "Linux")
	}
	if hasAnyPort(fp, 80, 443, 8080, 8443) || hasAnyService(fp, "http", "https") {
		tags = appendUniqueTags(tags, "HTTP")
	}
	if hasAnyPort(fp, 1433, 1434) || hasAnyService(fp, "mssql", "ms-sql") {
		tags = appendUniqueTags(tags, "MSSQL")
	}
	if hasAnyPort(fp, 53) || hasAnyService(fp, "domain", "dns") {
		tags = appendUniqueTags(tags, "DNS")
	}
	if hasAnyPort(fp, 389, 636, 3268, 3269) || hasAnyService(fp, "ldap") {
		tags = appendUniqueTags(tags, "LDAP")
	}
	if hasAnyPort(fp, 20, 21) || hasAnyService(fp, "ftp") {
		tags = appendUniqueTags(tags, "FTP")
	}
	if hasAnyPort(fp, 25, 465, 587) || hasAnyService(fp, "smtp") {
		tags = appendUniqueTags(tags, "SMTP")
	}
	if hasAnyPort(fp, 110, 995) || hasAnyService(fp, "pop3") {
		tags = appendUniqueTags(tags, "POP3")
	}
	if hasAnyPort(fp, 143, 993) || hasAnyService(fp, "imap") {
		tags = appendUniqueTags(tags, "IMAP")
	}
	if hasAnyPort(fp, 111, 2049) || hasAnyService(fp, "nfs", "rpcbind") {
		tags = appendUniqueTags(tags, "NFS")
	}
	if hasAnyPort(fp, 3306) || hasAnyService(fp, "mysql", "mariadb") {
		tags = appendUniqueTags(tags, "MYSQL")
	}
	if hasAnyPort(fp, 5432) || hasAnyService(fp, "postgres") {
		tags = appendUniqueTags(tags, "POSTGRES")
	}
	if hasAnyPort(fp, 6379) || hasAnyService(fp, "redis") {
		tags = appendUniqueTags(tags, "REDIS")
	}
	if hasAnyPort(fp, 1521) || hasAnyService(fp, "oracle") {
		tags = appendUniqueTags(tags, "ORACLE")
	}
	if hasAnyVNC(fp) || hasAnyService(fp, "vnc") {
		tags = appendUniqueTags(tags, "VNC")
	}
	if hasAnyPort(fp, 161, 162) || hasAnyService(fp, "snmp") {
		tags = appendUniqueTags(tags, "SNMP")
	}

	if len(tags) == 0 {
		return "UNKNOWN"
	}

	return strings.Join(tags, ", ")
}

func hasAllPorts(fp *hostFingerprint, ports ...int) bool {
	for _, port := range ports {
		if _, ok := fp.ports[port]; !ok {
			return false
		}
	}
	return true
}

func hasAnyPort(fp *hostFingerprint, ports ...int) bool {
	for _, port := range ports {
		if _, ok := fp.ports[port]; ok {
			return true
		}
	}
	return false
}

func hasAnyService(fp *hostFingerprint, needles ...string) bool {
	for _, service := range fp.services {
		for _, needle := range needles {
			if strings.Contains(service, needle) {
				return true
			}
		}
	}
	return false
}

func hasAnyVNC(fp *hostFingerprint) bool {
	for port := 5900; port <= 5906; port++ {
		if hasAnyPort(fp, port) {
			return true
		}
	}
	return false
}

func splitTagValues(raw string) []string {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag == "" {
			continue
		}
		out = append(out, tag)
	}
	return out
}

func appendUniqueTags(tags []string, candidate string) []string {
	if candidate == "" {
		return tags
	}

	normalized := strings.ToLower(strings.TrimSpace(candidate))
	for _, existing := range tags {
		if strings.ToLower(strings.TrimSpace(existing)) == normalized {
			return tags
		}
	}

	return append(tags, candidate)
}
