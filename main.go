package main

import (
"bufio"
"flag"
"fmt"
"log"
"os"
"strings"

"odin/core"
"odin/utils"
)

func main() {
targetDomain := flag.String("d", "", "Domínio alvo para o recon (ex: exemplo.com)")
listResults := flag.Bool("list", false, "Lista os serviços HTTP salvos no banco de dados do alvo especificado")
exportFile := flag.String("export", "", "Exporta URLs válidas (sem WAF) para um arquivo de texto")
statusFilter := flag.Int("status", 0, "Filtra -list por status code (0 = todos)")
configPath := flag.String("config", "config.yaml", "Caminho para o arquivo de configuração")
profile := flag.String("profile", "", "Sobrescreve o perfil definido no config.yaml (quick|standard|deep)")
flag.Parse()

cfg, found, err := core.LoadConfig(*configPath)
if err != nil {
log.Fatalf("Erro ao carregar configuração: %v", err)
}
if !found {
utils.LogWarning(fmt.Sprintf("Arquivo %s não encontrado, usando configuração padrão.", *configPath))
}

if *profile != "" {
cfg.Profile = strings.TrimSpace(*profile)
}

cleanDomain := strings.ToLower(strings.TrimSpace(*targetDomain))
cleanDomain = strings.ReplaceAll(cleanDomain, "/", "_")

if cleanDomain == "" && !*listResults && *exportFile == "" {
utils.LogError("É necessário informar um domínio alvo. Uso: odin -d exemplo.com")
os.Exit(1)
}

// Se for modo -list ou -export, precisamos do domínio para saber qual DB abrir
if *listResults || *exportFile != "" {
if cleanDomain == "" {
utils.LogError("Para usar -list ou -export, é necessário informar o alvo com -d. Ex: odin -list -d exemplo.com")
os.Exit(1)
}

dbName := fmt.Sprintf("%s_recon.db", cleanDomain)
if err := core.InitDB(dbName); err != nil {
log.Fatalf("Erro fatal ao inicializar banco de dados: %v", err)
}
defer core.CloseDB()

if *exportFile != "" {
exportCleanTargets(*exportFile, cleanDomain)
return
}

listHTTPServices(*statusFilter, cleanDomain)
return
}

// Modo Scan Normal
dbName := fmt.Sprintf("%s_recon.db", cleanDomain)
if err := core.InitDB(dbName); err != nil {
log.Fatalf("Erro fatal ao inicializar banco de dados: %v", err)
}
defer core.CloseDB()

if err := core.RunPipeline(cleanDomain, cfg); err != nil {
utils.LogError(fmt.Sprintf("Erro na execução do pipeline: %v", err))
os.Exit(1)
}
}

func exportCleanTargets(filename, targetName string) {
// Busca apenas serviços que NÃO são páginas de bloqueio
query := `SELECT url FROM http_services WHERE scan_id = (SELECT MAX(id) FROM scans) AND is_blockpage = 0 ORDER BY url`

rows, err := core.DB.Query(query)
if err != nil {
utils.LogError(fmt.Sprintf("Erro ao consultar o banco: %v", err))
os.Exit(1)
}
defer rows.Close()

file, err := os.Create(filename)
if err != nil {
utils.LogError(fmt.Sprintf("Erro ao criar arquivo de exportação: %v", err))
os.Exit(1)
}
defer file.Close()

writer := bufio.NewWriter(file)
count := 0

for rows.Next() {
var url string
if err := rows.Scan(&url); err != nil {
continue
}
writer.WriteString(url + "\n")
count++
}
writer.Flush()

if count == 0 {
utils.LogWarning("Nenhum alvo limpo encontrado para exportar.")
} else {
utils.LogSuccess(fmt.Sprintf("Exportação concluída: %d URLs limpas salvas em '%s' para o alvo %s.", count, filename, targetName))
}
}

func listHTTPServices(statusFilter int, targetName string) {
fmt.Printf("\n[*] Exibindo resultados para o alvo: %s\n", targetName)

query := `SELECT subdomain, port, status_code, tech, title, url, cdn, is_blockpage FROM ( SELECT host AS subdomain, port, status_code, tech, title, url, COALESCE(cdn, '') AS cdn, COALESCE(is_blockpage, 0) AS is_blockpage FROM http_services WHERE scan_id = (SELECT MAX(id) FROM scans) )`
args := []interface{}{}
if statusFilter != 0 {
query += " WHERE status_code = ?"
args = append(args, statusFilter)
}
query += " ORDER BY is_blockpage, status_code, subdomain"

rows, err := core.DB.Query(query, args...)
if err != nil {
utils.LogError(fmt.Sprintf("Erro ao consultar o banco: %v", err))
os.Exit(1)
}
defer rows.Close()

fmt.Println("\n--- SERVIÇOS HTTP ENCONTRADOS ---")
fmt.Printf("%-35s | %-6s | %-6s | %-25s | %-30s | %-12s | %s\n", "HOST", "PORTA", "STATUS", "TECNOLOGIAS", "TÍTULO", "CDN/WAF", "URL")
fmt.Println(repeatDash(155))

blockCount := 0
count := 0
for rows.Next() {
count++
var sub, tech, title, u, cdn string
var port, status, blocked int
if err := rows.Scan(&sub, &port, &status, &tech, &title, &u, &cdn, &blocked); err != nil {
utils.LogWarning(fmt.Sprintf("Erro ao ler linha: %v", err))
continue
}
titleCol := truncate(title, 30)
if blocked == 1 {
blockCount++
titleCol = "[[WAF?]] " + truncate(title, 23)
}
fmt.Printf("%-35s | %-6d | %-6d | %-25s | %-30s | %-12s | %s\n", sub, port, status, truncate(tech, 25), titleCol, truncate(cdn, 12), u)
}
if err := rows.Err(); err != nil {
utils.LogWarning(fmt.Sprintf("Erro ao iterar resultados: %v", err))
}

if count == 0 {
utils.LogWarning("Nenhum serviço HTTP encontrado para este alvo no banco de dados.")
} else {
fmt.Printf("\n[*] Total: %d serviços listados (%d marcados como [[WAF?]]).\n", count, blockCount)
}
}

func truncate(s string, n int) string {
if len(s) <= n {
return s
}
return s[:n-1] + "…"
}

func repeatDash(n int) string {
b := make([]byte, n)
for i := range b {
b[i] = '-'
}
return string(b)
}
