package modules

import (
"fmt"
"net/url"
"regexp"
"strings"

"odin/utils"

"github.com/projectdiscovery/katana/pkg/engine/standard"
"github.com/projectdiscovery/katana/pkg/output"
"github.com/projectdiscovery/katana/pkg/types"
)

type EndpointResult struct {
SourceURL  string
Endpoint   string
Method     string
HostsFound []string
}

type CrawlerOptions struct {
MaxDepth    int
Concurrency int
Parallelism int
RateLimit   int
}

var hostLikePattern = regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9-]{0,62}(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,62}){2,}`)

func RunCrawler(httpResults []HTTPResult, opts CrawlerOptions) ([]EndpointResult, error) {
utils.LogInfo(fmt.Sprintf("Iniciando crawling ativo (Katana) em %d aplicações web...", len(httpResults)))
var urls []string
seen := make(map[string]bool)
skipped := 0
for _, res := range httpResults {
if res.URL == "" {
continue
}
if res.BlockPage {
skipped++
continue
}
if seen[res.URL] {
continue
}
seen[res.URL] = true
urls = append(urls, res.URL)
}
if skipped > 0 {
utils.LogInfo(fmt.Sprintf("%d URLs puladas no crawling por serem provável página de bloqueio WAF.", skipped))
}
if len(urls) == 0 {
utils.LogWarning("Nenhuma URL válida encontrada para realizar crawling.")
return nil, nil
}

maxDepth := opts.MaxDepth
if maxDepth <= 0 {
maxDepth = 2
}
concurrency := opts.Concurrency
if concurrency <= 0 {
concurrency = 10
}
parallelism := opts.Parallelism
if parallelism <= 0 {
parallelism = 10
}
rateLimit := opts.RateLimit
if rateLimit <= 0 {
rateLimit = 150
}

var endpointResults []EndpointResult
options := &types.Options{
MaxDepth:    maxDepth,
Concurrency: concurrency,
Parallelism: parallelism,
RateLimit:   rateLimit,
Strategy:    "depth-first",
OnResult: func(result output.Result) {
if result.Request == nil || result.Request.URL == "" {
return
}
method := result.Request.Method
if method == "" {
method = "GET"
}
hostsFound := extractHosts(result.Request.URL)
if result.Response != nil {
hostsFound = append(hostsFound, extractHosts(result.Response.Body)...)
}
endpointResults = append(endpointResults, EndpointResult{
SourceURL:  result.Request.Source,
Endpoint:   result.Request.URL,
Method:     method,
HostsFound: hostsFound,
})
},
}

crawlerOptions, err := types.NewCrawlerOptions(options)
if err != nil {
return nil, fmt.Errorf("erro ao compilar opções do Katana: %w", err)
}
crawler, err := standard.New(crawlerOptions)
if err != nil {
return nil, fmt.Errorf("erro ao inicializar engine do Katana: %w", err)
}
defer crawler.Close()

for _, u := range urls {
if err := crawler.Crawl(u); err != nil {
utils.LogWarning(fmt.Sprintf("Falha ao realizar crawling na URL %s: %v", u, err))
}
}

utils.LogSuccess(fmt.Sprintf("Crawling concluído: %d endpoints/rotas descobertos.", len(endpointResults)))
return endpointResults, nil
}

func extractHosts(text string) []string {
var out []string
if parsed, err := url.Parse(text); err == nil && parsed.Host != "" {
out = append(out, strings.ToLower(parsed.Host))
}
for _, m := range hostLikePattern.FindAllString(text, -1) {
if looksLikeHost(m) {
out = append(out, strings.ToLower(m))
}
}
return out
}

func looksLikeHost(s string) bool {
if strings.Count(s, ".") < 2 {
return false
}
for _, part := range strings.Split(s, ".") {
if part == "" {
return false
}
}
return !isAllDigitsAndDots(s)
}

func isAllDigitsAndDots(s string) bool {
for _, r := range s {
if r != '.' && (r < '0' || r > '9') {
return false
}
}
return true
}
