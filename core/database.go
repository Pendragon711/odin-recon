package core

import (
"database/sql"
"fmt"
"os"
"path/filepath"
"time"

"odin/utils"

_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB(dbName string) error {
dbPath := filepath.Join("db", dbName)
if err := os.MkdirAll("db", os.ModePerm); err != nil {
return fmt.Errorf("erro ao criar diretório db/: %w", err)
}
database, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
if err != nil {
return fmt.Errorf("erro ao abrir banco de dados: %w", err)
}
database.SetMaxOpenConns(1)
DB = database
return createTables()
}

func createTables() error {
schema := `
CREATE TABLE IF NOT EXISTS scans (
id INTEGER PRIMARY KEY AUTOINCREMENT,
target TEXT NOT NULL,
profile TEXT,
started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
finished_at DATETIME,
status TEXT DEFAULT 'running'
);
CREATE TABLE IF NOT EXISTS subdomains (
id INTEGER PRIMARY KEY AUTOINCREMENT,
scan_id INTEGER NOT NULL,
host TEXT NOT NULL,
source TEXT NOT NULL,
first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
UNIQUE(scan_id, host, source)
);
CREATE TABLE IF NOT EXISTS dns_records (
id INTEGER PRIMARY KEY AUTOINCREMENT,
scan_id INTEGER NOT NULL,
host TEXT NOT NULL,
record_type TEXT NOT NULL,
value TEXT NOT NULL,
is_wildcard BOOLEAN DEFAULT 0,
discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
UNIQUE(scan_id, host, record_type, value)
);
CREATE TABLE IF NOT EXISTS ports (
id INTEGER PRIMARY KEY AUTOINCREMENT,
scan_id INTEGER NOT NULL,
host TEXT NOT NULL,
ip TEXT,
port INTEGER NOT NULL,
discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
UNIQUE(scan_id, host, port)
);
CREATE TABLE IF NOT EXISTS http_services (
id INTEGER PRIMARY KEY AUTOINCREMENT,
scan_id INTEGER NOT NULL,
host TEXT NOT NULL,
ip TEXT,
port INTEGER,
protocol TEXT,
status_code INTEGER,
title TEXT,
tech TEXT,
url TEXT NOT NULL,
content_length INTEGER,
body_hash TEXT,
simhash INTEGER,
favicon_hash TEXT,
server TEXT,
cdn TEXT,
is_blockpage BOOLEAN DEFAULT 0,
tls_sans TEXT,
first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
UNIQUE(scan_id, url)
);
CREATE TABLE IF NOT EXISTS endpoints (
id INTEGER PRIMARY KEY AUTOINCREMENT,
scan_id INTEGER NOT NULL,
source_url TEXT NOT NULL,
endpoint TEXT NOT NULL,
method TEXT DEFAULT 'GET',
discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
UNIQUE(scan_id, endpoint, method)
);
CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id, host);
CREATE INDEX IF NOT EXISTS idx_dns_scan ON dns_records(scan_id, host, record_type);
CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id, host);
CREATE INDEX IF NOT EXISTS idx_http_scan ON http_services(scan_id, status_code, host);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id, source_url);
`
_, err := DB.Exec(schema)
if err != nil {
return fmt.Errorf("erro ao criar tabelas: %w", err)
}

addColumns := []string{
`ALTER TABLE http_services ADD COLUMN cdn TEXT`,
`ALTER TABLE http_services ADD COLUMN is_blockpage BOOLEAN DEFAULT 0`,
`ALTER TABLE http_services ADD COLUMN simhash INTEGER`,
}
for _, stmt := range addColumns {
DB.Exec(stmt)
}
utils.LogSuccess("Banco de dados SQLite inicializado e tabelas estruturadas.")
return nil
}

func CloseDB() {
if DB != nil {
DB.Close()
}
}

func StartScan(target, profile string) (int64, error) {
res, err := DB.Exec(`INSERT INTO scans (target, profile, status) VALUES (?, ?, 'running')`, target, profile)
if err != nil {
return 0, fmt.Errorf("erro ao registrar scan: %w", err)
}
return res.LastInsertId()
}

func FinishScan(scanID int64, status string) error {
_, err := DB.Exec(`UPDATE scans SET status = ?, finished_at = ? WHERE id = ?`, status, time.Now(), scanID)
return err
}

func SaveSubdomains(scanID int64, hosts []string, source string) error {
stmt, err := DB.Prepare(`INSERT INTO subdomains (scan_id, host, source) VALUES (?, ?, ?) ON CONFLICT(scan_id, host, source) DO UPDATE SET last_seen = CURRENT_TIMESTAMP;`)
if err != nil {
return err
}
defer stmt.Close()
for _, h := range hosts {
if _, err := stmt.Exec(scanID, h, source); err != nil {
utils.LogWarning(fmt.Sprintf("Falha ao salvar subdomínio %s: %v", h, err))
}
}
return nil
}

type DNSRecordRow struct {
Host       string
RecordType string
Value      string
IsWildcard bool
}

func SaveDNSRecords(scanID int64, records []DNSRecordRow) error {
if len(records) == 0 {
return nil
}
tx, err := DB.Begin()
if err != nil {
return err
}
stmt, err := tx.Prepare(`INSERT INTO dns_records (scan_id, host, record_type, value, is_wildcard) VALUES (?, ?, ?, ?, ?) ON CONFLICT(scan_id, host, record_type, value) DO NOTHING;`)
if err != nil {
tx.Rollback()
return err
}
defer stmt.Close()
for _, r := range records {
if _, err := stmt.Exec(scanID, r.Host, r.RecordType, r.Value, r.IsWildcard); err != nil {
utils.LogWarning(fmt.Sprintf("Falha ao salvar registro DNS %s %s: %v", r.Host, r.RecordType, err))
}
}
return tx.Commit()
}

type PortRow struct {
Host string
IP   string
Port int
}

func SavePorts(scanID int64, rows []PortRow) error {
if len(rows) == 0 {
return nil
}
tx, err := DB.Begin()
if err != nil {
return err
}
stmt, err := tx.Prepare(`INSERT INTO ports (scan_id, host, ip, port) VALUES (?, ?, ?, ?) ON CONFLICT(scan_id, host, port) DO UPDATE SET ip = excluded.ip;`)
if err != nil {
tx.Rollback()
return err
}
defer stmt.Close()
for _, r := range rows {
if _, err := stmt.Exec(scanID, r.Host, r.IP, r.Port); err != nil {
utils.LogWarning(fmt.Sprintf("Falha ao salvar porta %s:%d: %v", r.Host, r.Port, err))
}
}
return tx.Commit()
}

type HTTPServiceRow struct {
Host          string
IP            string
Port          int
Protocol      string
StatusCode    int
Title         string
Tech          string
URL           string
ContentLength int
BodyHash      string
SimHash       uint64
FaviconHash   string
Server        string
CDN           string
IsBlockPage   bool
TLSSans       string
}

func SaveHTTPServices(scanID int64, rows []HTTPServiceRow) error {
if len(rows) == 0 {
return nil
}
tx, err := DB.Begin()
if err != nil {
return err
}
stmt, err := tx.Prepare(`INSERT INTO http_services (scan_id, host, ip, port, protocol, status_code, title, tech, url, content_length, body_hash, simhash, favicon_hash, server, cdn, is_blockpage, tls_sans) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(scan_id, url) DO UPDATE SET status_code = excluded.status_code, title = excluded.title, tech = excluded.tech, content_length = excluded.content_length, body_hash = excluded.body_hash, simhash = excluded.simhash, favicon_hash = excluded.favicon_hash, server = excluded.server, cdn = excluded.cdn, is_blockpage = excluded.is_blockpage, tls_sans = excluded.tls_sans, last_seen = CURRENT_TIMESTAMP;`)
if err != nil {
tx.Rollback()
return err
}
defer stmt.Close()
for _, r := range rows {
_, err := stmt.Exec(
scanID, r.Host, r.IP, r.Port, r.Protocol, r.StatusCode, r.Title, r.Tech, r.URL,
r.ContentLength, r.BodyHash, int64(r.SimHash), r.FaviconHash, r.Server, r.CDN, r.IsBlockPage, r.TLSSans,
)
if err != nil {
utils.LogWarning(fmt.Sprintf("Falha ao salvar serviço HTTP %s: %v", r.URL, err))
}
}
return tx.Commit()
}

type EndpointRow struct {
SourceURL string
Endpoint  string
Method    string
}

func SaveEndpoints(scanID int64, rows []EndpointRow) error {
if len(rows) == 0 {
return nil
}
tx, err := DB.Begin()
if err != nil {
return err
}
stmt, err := tx.Prepare(`INSERT INTO endpoints (scan_id, source_url, endpoint, method) VALUES (?, ?, ?, ?) ON CONFLICT(scan_id, endpoint, method) DO NOTHING;`)
if err != nil {
tx.Rollback()
return err
}
defer stmt.Close()
for _, r := range rows {
method := r.Method
if method == "" {
method = "GET"
}
if _, err := stmt.Exec(scanID, r.SourceURL, r.Endpoint, method); err != nil {
utils.LogWarning(fmt.Sprintf("Falha ao salvar endpoint %s: %v", r.Endpoint, err))
}
}
return tx.Commit()
}
