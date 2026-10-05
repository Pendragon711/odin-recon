package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"odin/core"
	"odin/utils"
)

func main() {
	targetDomain := flag.String("d", "", "Domínio alvo para o recon (ex: exemplo.com)")
	listResults := flag.Bool("list", false, "Lista os serviços HTTP salvos no banco de dados")
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
		cfg.Profile = *profile
	}

	if err := core.InitDB("odin_recon.db"); err != nil {
		log.Fatalf("Erro fatal ao inicializar banco de dados: %v", err)
	}
	defer core.CloseDB()

	if *listResults {
		listHTTPServices(*statusFilter)
		return
	}

	if *targetDomain == "" {
		utils.LogError("É necessário informar um domínio alvo. Uso: odin -d exemplo.com ou odin -list")
		os.Exit(1)
	}

	if err := core.RunPipeline(*targetDomain, cfg); err != nil {
		utils.LogError(fmt.Sprintf("Erro na execução do pipeline: %v", err))
		os.Exit(1)
	}
}

func listHTTPServices(statusFilter int) {
	query := `
		SELECT subdomain, port, status_code, tech, title, url, cdn, is_blockpage
		FROM (
			SELECT host AS subdomain, port, status_code, tech, title, url,
			       COALESCE(cdn, '') AS cdn, COALESCE(is_blockpage, 0) AS is_blockpage
			FROM http_services
		)
	`
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
	for rows.Next() {
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
	if blockCount > 0 {
		fmt.Printf("\n[*] %d linhas marcadas como [[WAF?]] = body_hash compartilhado por muitos hosts (provável página de bloqueio, não aplicação real).\n", blockCount)
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
