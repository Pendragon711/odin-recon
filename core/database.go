package core

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"odin/utils"

	_ "modernc.org/sqlite" // Driver SQLite puro em Go (não precisa de compilador C instalado no Windows)
)

var DB *sql.DB

// InitDB inicializa a conexão com o banco e cria a estrutura de tabelas.
func InitDB(dbName string) error {
	dbPath := filepath.Join("db", dbName)

	if err := os.MkdirAll("db", os.ModePerm); err != nil {
		return fmt.Errorf("erro ao criar diretório db/: %w", err)
	}

	database, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return fmt.Errorf("erro ao abrir banco de dados: %w", err)
	}

	// SQLite não lida bem com múltiplas escritas concorrentes; limitar a
	// uma conexão evita "database is locked" sem precisar de mutex externo.
	database.SetMaxOpenConns(1)

	DB = database

	return createTables()
}

func createTables() error {
	schema := `
	-- Uma linha por execução do Odin contra um alvo. Tudo se amarra em scan_id,
	-- então dá para rodar o mesmo alvo várias vezes sem misturar resultados
	-- e dá para comparar execuções (diff).
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		profile TEXT,
		started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		finished_at DATETIME,
		status TEXT DEFAULT 'running' -- running | completed | failed
	);

	-- Subdomínios/hosts candidatos e confirmados, com a fonte que os trouxe.
	CREATE TABLE IF NOT EXISTS subdomains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		host TEXT NOT NULL,
		source TEXT NOT NULL,       -- subfinder | bruteforce | permutation | tls_san | js | cname | crawler | manual
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(scan_id, host, source)
	);

	-- Registros DNS resolvidos por host. Um host pode ter vários registros
	-- do mesmo tipo (múltiplos A, por exemplo).
	CREATE TABLE IF NOT EXISTS dns_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		host TEXT NOT NULL,
		record_type TEXT NOT NULL, -- A | AAAA | CNAME | NS | MX | TXT
		value TEXT NOT NULL,
		is_wildcard BOOLEAN DEFAULT 0,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(scan_id, host, record_type, value)
	);

	-- Portas abertas por host/IP.
	CREATE TABLE IF NOT EXISTS ports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		host TEXT NOT NULL,
		ip TEXT,
		port INTEGER NOT NULL,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(scan_id, host, port)
	);

	-- Serviços HTTP/HTTPS confirmados, com os atributos usados para
	-- agrupar e priorizar ativos (hash de body/favicon, TLS, etc.).
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
		favicon_hash TEXT,
		server TEXT,
		cdn TEXT,                 -- CDN/WAF detectado pelo httpx (ex.: cloudflare)
		is_blockpage BOOLEAN DEFAULT 0, -- 1 = body_hash repetido em muitos hosts (ruído de WAF)
		tls_sans TEXT,            -- JSON array de SANs do certificado
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(scan_id, url)
	);

	-- Endpoints/rotas descobertos pelo crawler (antes eram descartados).
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

	// Migração leve para bancos criados em versões anteriores: SQLite não
	// aceita ADD COLUMN dentro de CREATE TABLE IF NOT EXISTS, então as
	// colunas novas são adicionadas aqui e erros de "duplicate column"
	// são silenciosamente ignorados (a coluna já existe).
	addColumns := []string{
		`ALTER TABLE http_services ADD COLUMN cdn TEXT`,
		`ALTER TABLE http_services ADD COLUMN is_blockpage BOOLEAN DEFAULT 0`,
	}
	for _, stmt := range addColumns {
		DB.Exec(stmt) // best-effort; schema acima já cobre bancos novos
	}

	utils.LogSuccess("Banco de dados SQLite inicializado e tabelas estruturadas.")
	return nil
}

// CloseDB encerra a conexão com o banco de dados.
func CloseDB() {
	if DB != nil {
		DB.Close()
	}
}

// StartScan cria uma linha de execução e devolve o scan_id a ser usado
// em todas as inserções desta rodada.
func StartScan(target, profile string) (int64, error) {
	res, err := DB.Exec(
		`INSERT INTO scans (target, profile, status) VALUES (?, ?, 'running')`,
		target, profile,
	)
	if err != nil {
		return 0, fmt.Errorf("erro ao registrar scan: %w", err)
	}
	return res.LastInsertId()
}

// FinishScan marca a execução como concluída ou falha.
func FinishScan(scanID int64, status string) error {
	_, err := DB.Exec(
		`UPDATE scans SET status = ?, finished_at = ? WHERE id = ?`,
		status, time.Now(), scanID,
	)
	return err
}

// SaveSubdomains grava candidatos/confirmados com a fonte de descoberta.
// Em conflito (mesmo host+fonte no mesmo scan), só atualiza last_seen.
func SaveSubdomains(scanID int64, hosts []string, source string) error {
	stmt, err := DB.Prepare(`
		INSERT INTO subdomains (scan_id, host, source)
		VALUES (?, ?, ?)
		ON CONFLICT(scan_id, host, source) DO UPDATE SET last_seen = CURRENT_TIMESTAMP;
	`)
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

// SaveDNSRecords grava registros DNS em lote dentro de uma transação,
// bem mais rápido que um INSERT por linha quando o volume é grande.
func SaveDNSRecords(scanID int64, records []DNSRecordRow) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO dns_records (scan_id, host, record_type, value, is_wildcard)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, host, record_type, value) DO NOTHING;
	`)
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
	stmt, err := tx.Prepare(`
		INSERT INTO ports (scan_id, host, ip, port)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(scan_id, host, port) DO UPDATE SET ip = excluded.ip;
	`)
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
	stmt, err := tx.Prepare(`
		INSERT INTO http_services
			(scan_id, host, ip, port, protocol, status_code, title, tech, url,
			 content_length, body_hash, favicon_hash, server, cdn, is_blockpage, tls_sans)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, url) DO UPDATE SET
			status_code = excluded.status_code,
			title = excluded.title,
			tech = excluded.tech,
			content_length = excluded.content_length,
			body_hash = excluded.body_hash,
			favicon_hash = excluded.favicon_hash,
			server = excluded.server,
			cdn = excluded.cdn,
			is_blockpage = excluded.is_blockpage,
			tls_sans = excluded.tls_sans,
			last_seen = CURRENT_TIMESTAMP;
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, r := range rows {
		_, err := stmt.Exec(
			scanID, r.Host, r.IP, r.Port, r.Protocol, r.StatusCode, r.Title, r.Tech, r.URL,
			r.ContentLength, r.BodyHash, r.FaviconHash, r.Server, r.CDN, r.IsBlockPage, r.TLSSans,
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
	stmt, err := tx.Prepare(`
		INSERT INTO endpoints (scan_id, source_url, endpoint, method)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(scan_id, endpoint, method) DO NOTHING;
	`)
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
