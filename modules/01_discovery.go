package modules

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"odin/utils"

	subrunner "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// defaultWordlist é uma lista pequena embutida para bruteforce quando
// nenhum arquivo é informado no config.yaml. É propositalmente curta —
// para cobertura séria, aponte "discovery.wordlist" para uma wordlist
// maior (ex: a lista "subdomains-top1million" da SecLists).
var defaultWordlist = []string{
	"www", "api", "dev", "staging", "stg", "test", "qa", "uat", "admin",
	"portal", "app", "mobile", "beta", "demo", "internal", "intranet",
	"vpn", "mail", "smtp", "ftp", "git", "gitlab", "jenkins", "ci", "cd",
	"docs", "status", "monitor", "grafana", "kibana", "elastic", "db",
	"mysql", "postgres", "redis", "cache", "cdn", "static", "assets",
	"img", "images", "media", "upload", "files", "backup", "old", "new",
	"v1", "v2", "api-dev", "api-staging", "sandbox", "preview", "preprod",
	"login", "auth", "sso", "accounts", "secure", "payment", "pay",
	"support", "help", "wiki", "confluence", "jira", "dashboard", "panel",
	"webmail", "ns1", "ns2", "mx", "mx1", "mx2",
}

// DiscoveryConfig espelha os campos relevantes de core.Config para
// este módulo não precisar importar o pacote core (evita ciclo).
type DiscoveryConfig struct {
	UseSubfinder bool
	Bruteforce   bool
	Permutations bool
	Wordlist     string
}

// DiscoveryResult mantém os hosts agrupados por fonte, para o engine
// gravar a proveniência de cada um no banco.
type DiscoveryResult struct {
	BySource map[string][]string
}

func (d *DiscoveryResult) AllHosts() []string {
	seen := make(map[string]bool)
	var all []string
	for _, hosts := range d.BySource {
		for _, h := range hosts {
			if !seen[h] {
				seen[h] = true
				all = append(all, h)
			}
		}
	}
	return all
}

func RunDiscovery(domain string, opts DiscoveryConfig) (*DiscoveryResult, error) {
	utils.LogInfo(fmt.Sprintf("Iniciando descoberta de subdomínios para: %s", domain))

	result := &DiscoveryResult{BySource: make(map[string][]string)}
	result.BySource["root"] = []string{strings.TrimSpace(domain)}

	if opts.UseSubfinder {
		hosts, err := runSubfinder(domain)
		if err != nil {
			// Subfinder sem API keys rende pouco e pode falhar por timeout
			// de alguma fonte — isso não deve derrubar o resto do discovery.
			utils.LogWarning(fmt.Sprintf("Subfinder falhou ou retornou vazio: %v", err))
		} else {
			result.BySource["subfinder"] = hosts
			utils.LogSuccess(fmt.Sprintf("Subfinder: %d hosts.", len(hosts)))
		}
	}

	if opts.Bruteforce {
		words := loadWordlist(opts.Wordlist)
		var bruteHosts []string
		for _, w := range words {
			bruteHosts = append(bruteHosts, fmt.Sprintf("%s.%s", w, domain))
		}
		result.BySource["bruteforce"] = bruteHosts
		utils.LogSuccess(fmt.Sprintf("Bruteforce: %d candidatos gerados (%d palavras).", len(bruteHosts), len(words)))
	}

	if opts.Permutations {
		seeds := append([]string{}, result.BySource["subfinder"]...)
		permHosts := generatePermutations(seeds, domain)
		if len(permHosts) > 0 {
			result.BySource["permutation"] = permHosts
			utils.LogSuccess(fmt.Sprintf("Permutação: %d candidatos gerados a partir de %d sementes.", len(permHosts), len(seeds)))
		}
	}

	utils.LogSuccess(fmt.Sprintf("Discovery concluído: %d hosts candidatos (todas as fontes).", len(result.AllHosts())))
	return result, nil
}

func runSubfinder(domain string) ([]string, error) {
	subfinderOptions := &subrunner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Silent:             true,
	}

	subfinderRunner, err := subrunner.NewRunner(subfinderOptions)
	if err != nil {
		return nil, fmt.Errorf("erro ao inicializar o Subfinder: %w", err)
	}

	outputBuffer := &bytes.Buffer{}
	_, err = subfinderRunner.EnumerateSingleDomainWithCtx(context.Background(), domain, []io.Writer{outputBuffer})
	if err != nil {
		return nil, fmt.Errorf("erro durante a enumeração: %w", err)
	}

	var hosts []string
	lines := strings.Split(outputBuffer.String(), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			hosts = append(hosts, trimmed)
		}
	}
	return hosts, nil
}

// loadWordlist usa um arquivo externo se configurado, senão a lista embutida.
func loadWordlist(path string) []string {
	if path == "" {
		return defaultWordlist
	}

	f, err := os.Open(path)
	if err != nil {
		utils.LogWarning(fmt.Sprintf("Não foi possível abrir wordlist '%s', usando a lista embutida: %v", path, err))
		return defaultWordlist
	}
	defer f.Close()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		w := strings.TrimSpace(scanner.Text())
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}
	if len(words) == 0 {
		return defaultWordlist
	}
	return words
}

// generatePermutations cria variações a partir dos hosts já conhecidos
// (ex.: "api.exemplo.com" -> "api-dev.exemplo.com", "dev-api.exemplo.com").
// É a técnica que mais compensa a ausência de fontes pagas: usa o que o
// próprio alvo já revelou como semente.
func generatePermutations(seeds []string, rootDomain string) []string {
	prefixes := []string{"dev", "stg", "staging", "test", "qa", "uat", "prod", "new", "old", "internal", "v2"}
	seen := make(map[string]bool)
	var out []string

	for _, seed := range seeds {
		sub := strings.TrimSuffix(seed, "."+rootDomain)
		if sub == "" || sub == seed {
			continue // não é subdomínio do alvo ou é o próprio root
		}
		firstLabel := strings.Split(sub, ".")[0]
		for _, p := range prefixes {
			candidates := []string{
				fmt.Sprintf("%s-%s.%s", p, firstLabel, rootDomain),
				fmt.Sprintf("%s-%s.%s", firstLabel, p, rootDomain),
			}
			for _, c := range candidates {
				if !seen[c] {
					seen[c] = true
					out = append(out, c)
				}
			}
		}
	}
	return out
}
