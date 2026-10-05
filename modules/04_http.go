package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"math/bits"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"odin/utils"

	"github.com/mfonda/simhash"
	"github.com/projectdiscovery/httpx/runner"
	"golang.org/x/time/rate"
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
	HashSource    string // "body" = mmh3 do corpo real; "header" = fallback p/ respostas sem corpo (redirects)
	SimHash       uint64 // simhash do corpo — resiste a mudanças dinâmicas (nonce/csrf/timestamp) que quebram o hash exato
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
	UserAgent       string
}

// probeTarget é uma URL explícita a testar, já amarrada ao resultado do
// naabu (host/IP/porta) — nada é adivinhado por nenhum dos lados.
type probeTarget struct {
	URL  string
	Info PortResult
}

// RunHTTPProbing testa cada combinação host:porta descoberta pelo naabu.
//
// Versões anteriores tinham dois efeitos colaterais graves observados em
// produção:
//
//  1. Enviar "host:porta" cru sem esquema fazia o httpx reatribuir portas
//     (hosts só-443 respondiam em :80 com URL/porta inconsistentes).
//     Correção: geramos explicitamente http://host:porta e
//     https://host:porta por combinação.
//
//  2. Com Hashes habilitado, o httpx injetava mmh3+simhash do BODY em
//     TODAS as respostas — inclusive redirects 301/302 com corpo vazio.
//     Resultado: todos os redirects compartilhavam o hash "-1840324437"
//     (mmh3 do corpo base64 de ""), a detecção de página de bloqueio
//     marcava 100% das linhas como [[WAF?]] e o crawler ficava sem
//     nenhuma URL. Correção: não usamos options.Hashes; extraímos o
//     corpo DECODIFICADO real via r.Response.Data (o mesmo slice que o
//     httpx hashearia) e só computamos mmh3/simhash quando ele é não
//     vazio. Nunca parseamos r.Raw para obter o corpo: em respostas
//     gzip/deflate/chunked o Raw contém bytes binários pós-headers que
//     corrompem qualquer split por \r\n\r\n (foi a fonte do bug do
//     "18446744073709551615", simhash ~0xFFFF... de lixo binário).
//
// Rate limit: além do RateLimit interno do httpx, um limiter global
// (golang.org/x/time/rate) segura o OnResult, garantindo que a taxa
// efetiva de requisições respeite rate_limit.global_rps do config.
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

	targetMap := make(map[string]probeTarget)
	for _, res := range portResults {
		// Duas URLs explícitas por host:porta — determinístico, sem
		// heurística de esquema nem reatribuição de porta.
		for _, scheme := range []string{"http", "https"} {
			target := fmt.Sprintf("%s://%s:%d", scheme, res.Subdomain, res.Port)
			if _, dup := targetMap[target]; dup {
				continue
			}
			targetMap[target] = probeTarget{URL: target, Info: res}
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
	userAgent := opts.UserAgent
	if userAgent == "" {
		userAgent = defaultUserAgent
	}

	rps := effectiveRPS(opts.GlobalRPS)
	limiter := rate.NewLimiter(rate.Limit(rps), 1)

	var mu sync.Mutex
	var results []HTTPResult
	seenURL := make(map[string]bool)

	options := runner.Options{
		Methods:            "GET",
		InputFile:          tmpFile.Name(),
		StatusCode:         true,
		TechDetect:         true,
		ExtractTitle:       true,
		OutputServerHeader: true,
		// Em httpx >= v1.9 os headers da resposta já vêm em
		// r.ResponseHeaders/r.RawHeaders no Result; não existe opção
		// para ligar/desligar isso (o antigo campo ResponseHeaders e o
		// UserAgent saíram de runner.Options).
		CustomHeaders:      []string{"User-Agent: " + userAgent},
		FollowRedirects:    opts.FollowRedirects,
		Threads:            threads,
		RateLimit:          rps, // limite de req/s dentro do próprio httpx
		Timeout:            timeout,
		TLSGrab:            true, // necessário para popular r.TLSData com os SANs
		DisableUpdateCheck: true,
		// IMPORTANTE: sem options.Hashes aqui — ver doc acima. Os hashes
		// de corpo são calculados manualmente só quando existe corpo.
		OnResult: func(r runner.Result) {
			// Gargalo global: segura o pipeline de saída à taxa configurada.
			_ = limiter.Wait(context.Background())

			key := strings.TrimSpace(r.Input)
			origInfo, exists := targetMap[key]
			if !exists {
				origInfo = probeTarget{Info: PortResult{Subdomain: r.Host}}
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

			// --- Hashes: corpo DECODIFICADO real via r.Response.Data ---
			// É exatamente o slice que o httpx hashearia com -hash mmh3,simhash
			// (resp.Data), e já vem com gzip/chunked decodificados. NÃO
			// parseamos r.Raw: em respostas comprimidas/transfer-encoding o
			// Raw tem bytes binários pós-headers que quebram qualquer split
			// por \r\n\r\n e geram hashes de lixo (o bug do simhash
			// 18446744073709551615 visto no scan da uems.br).
			var body []byte
			if r.Response != nil {
				body = r.Response.Data
			}
			bodyHash, simHash := computeBodyHashes(body)

			// Fallback honesto para redirects/304 sem corpo: em vez de
			// hashear o corpo vazio (todos colidiriam no mesmo hash e a
			// detecção de WAF marcaria 100% das linhas), agrupamos
			// redirects pelo DESTINO (Location normalizada). Redirecionar
			// muitos hosts para um mesmo portal é comportamento normal de
			// infraestrutura — nunca sinal de bloqueio. Se houver corpo
			// real (ex.: 503 com página genérica), o hash do corpo entra
			// normalmente na detecção.
			hashSource := "body"
			if bodyHash == "" || bodyHash == emptyBodyMmh3 {
				bodyHash = redirectGroupKey(r)
				hashSource = "redirect"
			}

			// Dedupe por URL final: o httpx entrega a mesma resposta tanto
			// para o input original quanto para a Location seguida
			// (r.Input == r.URL). Sem isso o -list fica cheio de linhas
			// duplicadas.
			urlFinal := r.URL
			if urlFinal == "" {
				urlFinal = key
			}
			mu.Lock()
			dup := seenURL[urlFinal]
			seenURL[urlFinal] = true
			mu.Unlock()
			if dup {
				return
			}

			// Porta: sempre derivada da URL que realmente respondeu
			// (que foi construída a partir da porta confirmada pelo
			// naabu), com fallback para a porta do alvo.
			port := origInfo.Info.Port
			if u, err := url.Parse(urlFinal); err == nil {
				if p := u.Port(); p != "" {
					if pi, err := strconv.Atoi(p); err == nil && pi > 0 {
						port = pi
					}
				} else if u.Scheme == "https" {
					port = 443
				} else if u.Scheme == "http" {
					port = 80
				}
			}

			mu.Lock()
			results = append(results, HTTPResult{
				Subdomain:     origInfo.Info.Subdomain,
				IP:            origInfo.Info.IP,
				Port:          port,
				Protocol:      r.Scheme,
				StatusCode:    r.StatusCode,
				Tech:          techStr,
				Title:         r.Title,
				URL:           urlFinal,
				ContentLength: r.ContentLength,
				BodyHash:      bodyHash,
				HashSource:    hashSource,
				SimHash:       simHash,
				FaviconHash:   r.FavIconMMH3,
				Server:        r.WebServer,
				CDNName:       r.CDNName,
				TLSSans:       sans,
				TLSSansJSON:   string(sansJSON),
			})
			mu.Unlock()
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

// defaultUserAgent: um UA de navegador comum. O default do httpx se
// identifica como ferramenta de scanner ("httpx/..."), o que é convite
// para WAF/anti-bot servir página de bloqueio.
const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

// emptyBodyMmh3 é o mmh3 que o httpx calcularia para um corpo vazio
// (stdBase64("") == "\n"). Comparar contra esse valor nos permite
// detectar "não há corpo real" em vez de hashar o vazio cegamente —
// foi exatamente isso que marcou 100% dos redirects como [[WAF?]].
var emptyBodyMmh3 = hashes.Mmh3(nil)

// splitRawResponse separa headers e corpo de uma resposta HTTP crua
// (mesma convenção do httpx: primeiro \r\n\r\n ou \n\n).
func splitRawResponse(raw []byte) (headers, body []byte) {
	if idx := bytesIndexPair(raw); idx >= 0 {
		return raw[:idx], raw[idx:]
	}
	return raw, nil
}

func bytesIndexPair(raw []byte) int {
	crlf := bytes.Index(raw, []byte("\r\n\r\n"))
	lf := bytes.Index(raw, []byte("\n\n"))
	switch {
	case crlf < 0 && lf < 0:
		return -1
	case crlf < 0:
		return lf + 2
	case lf < 0:
		return crlf + 4
	case lf < crlf:
		return lf + 2
	default:
		return crlf + 4
	}
}

// computeBodyHashes replica o cálculo do flag -hash mmh3,simhash do
// httpx (usando as MESMAS funções do pacote common/hashes, portanto os
// valores são idênticos aos que o httpx reportaria), mas devolve
// simhash somente quando existe corpo real. Simhash sobre corpo vazio
// é sempre ~0xFFFF... (todos os bits ligados, pois o vetor zerado é
// ">= 0" em todas as posições) — inútil como fingerprint e fonte de
// falsos positivos.
func computeBodyHashes(raw []byte) (bodyMmh3 string, bodySimhash uint64) {
	_, body := splitRawResponse(raw)
	if len(bytes.TrimSpace(body)) == 0 {
		return "", 0
	}
	bodyMmh3 = hashes.Mmh3(body)
	bodySimhash = simhash.Simhash(simhash.NewWordFeatureSet(body))
	return bodyMmh3, bodySimhash
}

// redirectGroupKey agrupa respostas sem corpo pela Location (destino do
// redirect), normalizada sem query/fragment. Retorna "" quando não há
// Location aproveitável — nesse caso a linha fica fora da detecção de
// página de bloqueio (não marcamos no escuro).
func redirectGroupKey(r runner.Result) string {
	loc := strings.TrimSpace(r.Location)
	if loc == "" {
		for k, v := range r.ResponseHeaders {
			if !strings.EqualFold(k, "location") {
				continue
			}
			switch t := v.(type) {
			case string:
				loc = strings.TrimSpace(t)
			case []string:
				if len(t) > 0 {
					loc = strings.TrimSpace(t[0])
				}
			case []interface{}:
				if len(t) > 0 {
					loc = strings.TrimSpace(fmt.Sprintf("%v", t[0]))
				}
			}
			break
		}
	}
	if loc == "" {
		return ""
	}
	if u, err := url.Parse(loc); err == nil {
		u.Path = strings.TrimRight(u.Path, "/")
		u.RawQuery = ""
		u.Fragment = ""
		return u.String()
	}
	return loc
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

// blockPageMinURLs: número de URLs do MESMO fingerprint dentro de um
// mesmo host que, combinado com >=2 hosts, indica página de bloqueio
// servida em série (anti-bot por host, não apenas por domínio inteiro).
const blockPageMinURLs = 3

// blockPageSingleHostDominance: se UM único host devolve o mesmo
// fingerprint em N+ páginas diferentes, é dominância de template de
// bloqueio/erro naquele host — mesmo sem outros hosts no cluster.
const blockPageSingleHostDominance = 10

// similarityLayerMinResults: abaixo deste volume de respostas a camada
// de similaridade (simhash) fica desligada. Com poucos ativos, dois
// sites parecidos são explicação mais provável que WAF — foi o falso
// positivo visto em produção (cluster de 4 hosts legítimos marcou como
// [[WAF?]] "similar").
const similarityLayerMinResults = 8

// simhashHammingThreshold: distância máxima de bits entre dois simhashes
// para considerarmos os corpos "quase idênticos". Em 64 bits, <=3 é
// conservador (falsos positivos raros); páginas de bloqueio com nonce/CSRF
// dinâmico mudam poucos tokens do corpo e caem nessa faixa.
const simhashHammingThreshold = 3

func markBlockPages(results []HTTPResult) {
	// Pré-filtro: respostas sem corpo (redirects) são agrupadas pelo
	// DESTINO e nunca contam como página de bloqueio — muitos hosts
	// apontando para o mesmo portal é infraestrutura legítima. Só
	// fingerprints de CORPO entram na detecção.
	type key = string
	joinable := func(r HTTPResult) (key, bool) {
		if r.BodyHash == "" || r.HashSource != "body" {
			return "", false
		}
		return r.BodyHash, true
	}

	hostsByGroup := make(map[key]map[string]int) // grupo -> host -> qtde de URLs
	for _, r := range results {
		k, ok := joinable(r)
		if !ok {
			continue
		}
		if hostsByGroup[k] == nil {
			hostsByGroup[k] = make(map[string]int)
		}
		hostsByGroup[k][r.Subdomain]++
	}
	// Marca quando o MESMO fingerprint aparece em N+ hosts distintos
	// OU domina a resposta de UM único host com muitas páginas diferentes
	// (ex.: portal com 20 rotas todas devolvendo "Attack Detected").
	markIfNoise := func(k key, host string, i int) {
		hosts := hostsByGroup[k]
		if len(hosts) >= blockPageMinHosts || (len(hosts) >= 2 && hosts[host] >= blockPageMinURLs) {
			results[i].BlockPage = true
			results[i].BlockReason = "exact"
		}
	}
	for i, r := range results {
		if k, ok := joinable(r); ok {
			markIfNoise(k, r.Subdomain, i)
		}
	}

	// Camada 2 — similaridade (simhash): pega a página de bloqueio quando
	// ela embute um token dinâmico (nonce, CSRF, timestamp) que muda o
	// body_hash exato a cada resposta. Só entra em jogo se o alvo tem
	// volume suficiente p/ sustentar a estatística; abaixo disso,
	// similaridade entre poucos hosts é mais explicada por templates
	// legítimos (mesmo CMS) do que por WAF. Agrupa por proximidade de
	// Hamming via "pigeonhole": se dois simhashes diferem em <=T bits,
	// eles obrigatoriamente coincidem em pelo menos um dos T+1 blocos de
	// 64/(T+1) bits — então basta comparar candidatos que compartilham
	// algum bloco, sem fazer O(n²).
	if len(results) < similarityLayerMinResults {
		return
	}

	type shEntry struct {
		idx  int
		hash uint64
	}
	buckets := make(map[[2]interface{}][]shEntry) // {bloco i, valor} -> entradas
	for i, r := range results {
		if r.SimHash == 0 || r.HashSource != "body" {
			continue // simhash só existe/faz sentido p/ corpo real
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
		if results[i].SimHash != 0 && results[i].HashSource == "body" {
			parent[i] = i
		}
	}
	for _, entries := range buckets {
		for _, e := range entries {
			for _, f := range entries {
				if e.idx >= f.idx {
					continue
				}
				if bits.OnesCount64(e.hash^f.hash) <= simhashHammingThreshold {
					union(e.idx, f.idx)
				}
			}
		}
	}

	urlsByCluster := make(map[int]int)
	hostsByCluster := make(map[int]map[string]bool)
	for i, r := range results {
		if r.SimHash == 0 || r.HashSource != "body" {
			continue
		}
		root := find(i)
		urlsByCluster[root]++
		if hostsByCluster[root] == nil {
			hostsByCluster[root] = make(map[string]bool)
		}
		hostsByCluster[root][r.Subdomain] = true
	}
	for i := range results {
		if results[i].BlockPage || results[i].SimHash == 0 || results[i].HashSource != "body" {
			continue
		}
		root := find(i)
		hosts := hostsByCluster[root]
		if len(hosts) >= blockPageMinHosts ||
			(len(hosts) >= 2 && urlsByCluster[root] >= blockPageMinURLs) ||
			urlsByCluster[root] >= blockPageSingleHostDominance {
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
