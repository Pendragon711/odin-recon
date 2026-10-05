package modules

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"strconv"

	"odin/utils"

	"github.com/projectdiscovery/httpx/runner"
)

type HTTPResult struct {
	Subdomain     string
	IP            string
	Port          int
	Protocol      string
	StatusCode    int
	Tech          string
	Title         string
	URL           string
	ContentLength int
	BodyHash      string
	SimHash       uint64   // simhash do corpo — resiste a mudanças dinâmicas (nonce/csrf/timestamp) que quebram o hash exato
	FaviconHash   string
	Server        string
	CDNName       string   // nome do CDN/WAF reportado pelo httpx (ex.: cloudflare)
	BlockPage     bool     // marcado post-scan: body_hash/simhash repetido em muitos hosts
	BlockReason   string   // "exact" = mesmo body_hash; "similar" = bodies quase idênticos (simhash)
	TLSSans       []string // hosts extraídos do certificado, para retroalimentação
	TLSSansJSON   string   // mesmo conteúdo serializado, para gravar no banco
}

type HTTPOptions struct {
	Threads         int
	TimeoutSeconds  int
	FollowRedirects bool
	GlobalRPS       int // rate_limit.global_rps do config — agora realmente usado
}

// RunHTTPProbing testa cada combinação host:porta descoberta pelo naabu.
//
// Versão anterior enviava "host:porta" cru sem esquema e dependia do
// httpx "adivinhar" http vs https — efeito colateral observado em
// produção: hosts só-443 eram testados em :80 e salvos com URL/porta
// inconsistentes. Agora geramos explicitamente http://host:porta e
// https://host:porta para cada combinação; o httpx testa exatamente o
// que mandamos e a porta registrada vem da URL real da resposta
// (fallback: a porta do naabu). Nada é adivinhado por nenhum dos lados.
func RunHTTPProbing(portResults []PortResult, opts HTTPOptions) ([]HTTPResult, error) {
	utils.LogInfo(fmt.Sprintf("Iniciando sondagem HTTP/HTTPS para %d alvos...", len(portResults)))

	if len(portResults) == 0 {
		utils.LogWarning("Nenhuma porta aberta encontrada para realizar a sondagem HTTP.")
		return nil, nil
	}

	tmpFile, err := os.CreateTemp("", "httpx-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("erro ao criar arquivo temporário: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	targetMap := make(map[string]PortResult)
	for _, res := range portResults {
		// Duas URLs explícitas por host:porta — determinístico, sem
		// heurística de esquema nem reatribuição de porta.
		for _, scheme := range []string{"http", "https"} {
			target := fmt.Sprintf("%s://%s:%d", scheme, res.Subdomain, res.Port)
			targetMap[target] = res
			tmpFile.WriteString(target + "\n")
		}
	}
	tmpFile.Close()

	threads := opts.Threads
	if threads <= 0 {
		threads = 25
	}
	timeout := opts.TimeoutSeconds
	if timeout <= 0 {
		timeout = 10
	}

	var results []HTTPResult

	options := runner.Options{
		Methods:              "GET",
		InputFile:            tmpFile.Name(),
		StatusCode:           true,
		TechDetect:           true,
		ExtractTitle:         true,
		OutputServerHeader:   true,
		Hashes:              "mmh3,simhash", // body_mmh3 (idêntico) + body_simhash (quase-idêntico, resiste a nonce/CSRF/timestamp no HTML)
		Favicon:              true,   // popula FavIconMMH3 (hash clássico tipo Shodan/search engines)
		FollowRedirects:      opts.FollowRedirects,
		Threads:              threads,
		RateLimit:            effectiveRPS(opts.GlobalRPS), // limite REAL de req/s no httpx
		Timeout:              timeout,
		TLSGrab:              true, // necessário para popular r.TLSData com os SANs
		DisableUpdateCheck:   true,
		OnResult: func(r runner.Result) {
			key := r.Input
			origInfo, exists := targetMap[key]
			if !exists {
				origInfo = PortResult{Subdomain: r.Host}
			}

			techStr := ""
			if len(r.Technologies) > 0 {
				techStr = joinComma(r.Technologies)
			}

			var sans []string
			if r.TLSData != nil {
				sans = append(sans, r.TLSData.SubjectAN...)
			}
			sansJSON, _ := json.Marshal(sans)

			bodyHash := ""
			var simHash uint64
			faviconHash := r.FavIconMMH3
			if r.Hashes != nil {
				if v, ok := r.Hashes["body_mmh3"]; ok {
					bodyHash = fmt.Sprintf("%v", v)
				}
				// httpx serializa o simhash como número decimal em string.
				if v, ok := r.Hashes["body_simhash"]; ok {
					if sh, err := strconv.ParseUint(fmt.Sprintf("%v", v), 10, 64); err == nil {
						simHash = sh
					}
				}
			}

			// Porta: confia na URL que realmente respondeu; se vier sem
			// porta explícita, cai para a porta do alvo (naabu).
			port := origInfo.Port
			if p, err := strconv.Atoi(r.Port); err == nil && p > 0 {
				port = p
			}

			results = append(results, HTTPResult{
				Subdomain:     origInfo.Subdomain,
				IP:            origInfo.IP,
				Port:          port,
				Protocol:      r.Scheme,
				StatusCode:    r.StatusCode,
				Tech:          techStr,
				Title:         r.Title,
				URL:           r.URL,
				ContentLength: r.ContentLength,
				BodyHash:      bodyHash,
				SimHash:       simHash,
				FaviconHash:   faviconHash,
				Server:        r.WebServer,
				CDNName:       r.CDNName,
				TLSSans:       sans,
				TLSSansJSON:   string(sansJSON),
			})
		},
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		return nil, fmt.Errorf("erro ao inicializar o httpx: %w", err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	// Detecção de página de bloqueio compartilhada (WAF/anti-bot):
	// o mesmo body_hash aparecendo em muitos hosts diferentes não são
	// "muitas aplicações iguais" — é quase certamente uma única página
	// de bloqueio servida a requests automatizados. Marcamos como ruído
	// para o -list não tratar bloqueio como dado legítimo.
	markBlockPages(results)

	utils.LogSuccess(fmt.Sprintf("Sondagem HTTP concluída: %d respostas (%d sinalizadas como provável página de bloqueio WAF).",
		len(results), countMarked(results)))
	return results, nil
}

// effectiveRPS aplica um teto conservador: acima de ~100 req/s contra um
// único alvo é convite para disparar WAF/anti-bot (que foi exatamente o
// que aconteceu no scan da ufms.br). O valor do config continua mandando,
// mas nunca passa do teto de cortesia.
func effectiveRPS(cfgRPS int) int {
	const ceiling = 100
	if cfgRPS <= 0 {
		return 50 // default seguro quando o campo não está setado
	}
	if cfgRPS > ceiling {
		return ceiling
	}
	return cfgRPS
}

// blockPageMinHosts: a partir de quantos hosts DISTINTOS compartilhando o
// mesmo body_hash consideramos "página de bloqueio" e não aplicação real.
const blockPageMinHosts = 5

// simhashHammingThreshold: distância máxima de bits entre dois simhashes
// para considerarmos os corpos "quase idênticos". Em 64 bits, <=3 é
// conservador (falsos positivos raros); páginas de bloqueio com nonce/CSRF
// dinâmico mudam poucos tokens do corpo e caem nessa faixa.
const simhashHammingThreshold = 3

func markBlockPages(results []HTTPResult) {
	hostByHash := make(map[string]map[string]bool)
	for _, r := range results {
		if r.BodyHash == "" {
			continue
		}
		if hostByHash[r.BodyHash] == nil {
			hostByHash[r.BodyHash] = make(map[string]bool)
		}
		hostByHash[r.BodyHash][r.Subdomain] = true
	}
	for i := range results {
		if results[i].BodyHash == "" {
			continue
		}
		if len(hostByHash[results[i].BodyHash]) >= blockPageMinHosts {
			results[i].BlockPage = true
			results[i].BlockReason = "exact"
		}
	}

	// Camada 2 — similaridade (simhash): pega a página de bloqueio quando
	// ela embute um token dinâmico (nonce, CSRF, timestamp) que muda o
	// body_hash exato a cada resposta. Agrupa por proximidade de Hamming
	// via "pigeonhole": se dois simhashes diferem em <=T bits, eles
	// obrigatoriamente coincidem em pelo menos um dos T+1 blocos de
	// 64/(T+1) bits — então basta comparar candidatos que compartilham
	// algum bloco, sem fazer O(n²).
	type shEntry struct {
		idx  int
		hash uint64
	}
	buckets := make(map[[2]interface{}][]shEntry) // {bloco i, valor} -> entradas
	for i, r := range results {
		if r.SimHash == 0 {
			continue
		}
		nblocks := simhashHammingThreshold + 1
		blockBits := 64 / nblocks
		for b := 0; b < nblocks; b++ {
			key := [2]interface{}{b, (r.SimHash >> (uint(b) * uint(blockBits))) & ((uint64(1) << blockBits) - 1)}
			buckets[key] = append(buckets[key], shEntry{idx: i, hash: r.SimHash})
		}
	}

	// Union-find simples sobre índices para formar clusters de bodies similares.
	parent := make(map[int]int)
	find := func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
		}
	}
	for i := range results {
		if results[i].SimHash != 0 {
			parent[i] = i
		}
	}
	for _, entries := range buckets {
		for _, e := range entries {
			for _, f := range entries {
				if e.idx >= f.idx {
					continue
				}
				if bits.OnesCount64(e.hash ^ f.hash) <= simhashHammingThreshold {
					union(e.idx, f.idx)
				}
			}
		}
	}

	hostsByCluster := make(map[int]map[string]bool)
	for i, r := range results {
		if r.SimHash == 0 {
			continue
		}
		root := find(i)
		if hostsByCluster[root] == nil {
			hostsByCluster[root] = make(map[string]bool)
		}
		hostsByCluster[root][r.Subdomain] = true
	}
	for i := range results {
		if results[i].BlockPage || results[i].SimHash == 0 {
			continue
		}
		if len(hostsByCluster[find(i)]) >= blockPageMinHosts {
			results[i].BlockPage = true
			results[i].BlockReason = "similar"
		}
	}
}

func countMarked(results []HTTPResult) int {
	n := 0
	for _, r := range results {
		if r.BlockPage {
			n++
		}
	}
	return n
}

func joinComma(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
