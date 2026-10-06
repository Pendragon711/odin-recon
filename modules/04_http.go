package modules

import (
"bytes"
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

"github.com/projectdiscovery/httpx/common/hashes"
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
HashSource    string
SimHash       uint64
FaviconHash   string
Server        string
CDNName       string
BlockPage     bool
BlockReason   string
TLSSans       []string
TLSSansJSON   string
}

type HTTPOptions struct {
Threads         int
TimeoutSeconds  int
FollowRedirects bool
GlobalRPS       int
UserAgent       string
}

type probeTarget struct {
URL  string
Info PortResult
}

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
CustomHeaders:      []string{"User-Agent: " + userAgent},
FollowRedirects:    opts.FollowRedirects,
Threads:            threads,
RateLimit:          rps,
Timeout:            timeout,
TLSGrab:            true,
DisableUpdateCheck: true,
OnResult: func(r runner.Result) {
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

body := r.ResponseBody
if body == "" && r.Raw != "" {
body = r.Raw
}
bodyHash, simHash := computeBodyHashes(body)

hashSource := "body"
if bodyHash == "" || bodyHash == emptyBodyMmh3 {
bodyHash = redirectGroupKey(r)
hashSource = "redirect"
}

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

markBlockPages(results)
utils.LogSuccess(fmt.Sprintf("Sondagem HTTP concluída: %d respostas (%d sinalizadas como provável página de bloqueio WAF).",
len(results), countMarked(results)))
return results, nil
}

const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
var emptyBodyMmh3 = hashes.Mmh3(nil)

func computeBodyHashes(body string) (bodyMmh3 string, bodySimhash uint64) {
raw := bytes.TrimSpace([]byte(body))
if len(raw) == 0 {
return "", 0
}
bodyMmh3 = hashes.Mmh3(raw)
// Usa a função utils.Simhash nativa que criamos anteriormente
bodySimhash = utils.Simhash(raw)
return bodyMmh3, bodySimhash
}

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

func effectiveRPS(cfgRPS int) int {
const ceiling = 100
if cfgRPS <= 0 {
return 50
}
if cfgRPS > ceiling {
return ceiling
}
return cfgRPS
}

const blockPageMinHosts = 8
const blockPageMinURLs = 3
const blockPageSingleHostDominance = 10
const similarityLayerMinResults = 15
const simhashHammingThreshold = 3

func clusterLooksLikeBlock(allResults []HTTPResult, hosts map[string]bool) bool {
blocky := 0
total := 0
for _, r := range allResults {
if _, ok := hosts[r.Subdomain]; !ok {
continue
}
total++
if r.StatusCode == 403 || r.StatusCode == 429 || r.StatusCode == 503 {
blocky++
}
}
return total > 0 && blocky*2 >= total
}

// wafKeywords contém termos comuns em páginas de bloqueio de WAF/IPS.
var wafKeywords = []string{
"attack detected",
"access denied",
"blocked",
"imperva",
"incapsula",
"request rejected",
"web application firewall",
"suspicious activity",
"invalid request",
"your request was blocked",
"forbidden",
}

// hasWAFSignature verifica se o título ou metadados da resposta contêm 
// assinaturas clássicas de bloqueio, independentemente do status code.
func hasWAFSignature(title, cdn, server string) bool {
lowerTitle := strings.ToLower(title)
for _, kw := range wafKeywords {
if strings.Contains(lowerTitle, kw) {
return true
}
}
return false
}

func markBlockPages(results []HTTPResult) {
// 1. DETECÇÃO POR ASSINATURA (Keyword Fallback)
// Marca imediatamente se o título contiver palavras-chave clássicas de WAF.
// Isso captura os falsos "200 OK" com "Attack Detected" que o clustering ignora.
for i := range results {
if hasWAFSignature(results[i].Title, results[i].CDNName, results[i].Server) {
results[i].BlockPage = true
results[i].BlockReason = "signature"
}
}

// 2. DETECÇÃO POR CLUSTERING (Lógica original)
type key = string
joinable := func(r HTTPResult) (key, bool) {
// Se já foi marcado por assinatura, não precisa clusterizar
if r.BlockPage {
return "", false
}
if r.BodyHash == "" || r.HashSource != "body" {
return "", false
}
if r.StatusCode != 200 && r.StatusCode != 503 && r.StatusCode != 403 && r.StatusCode != 429 {
return "", false
}
return r.BodyHash, true
}

hostsByGroup := make(map[key]map[string]int)
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

markIfNoise := func(k key, host string, i int) {
hosts := hostsByGroup[k]
if len(hosts) >= blockPageMinHosts || (len(hosts) >= 2 && hosts[host] >= blockPageMinURLs) {
blockHosts := make(map[string]bool, len(hostsByGroup[k]))
for h := range hostsByGroup[k] {
blockHosts[h] = true
}
if !clusterLooksLikeBlock(results, blockHosts) {
return
}
results[i].BlockPage = true
results[i].BlockReason = "exact"
}
}

for i, r := range results {
if k, ok := joinable(r); ok {
markIfNoise(k, r.Subdomain, i)
}
}

if len(results) < similarityLayerMinResults {
return
}

type shEntry struct {
idx  int
hash uint64
}
buckets := make(map[[2]interface{}][]shEntry)
for i, r := range results {
if r.SimHash == 0 || r.HashSource != "body" {
if r.StatusCode >= 300 && r.StatusCode < 400 {
continue
}
continue
}
nblocks := simhashHammingThreshold + 1
blockBits := 64 / nblocks
for b := 0; b < nblocks; b++ {
key := [2]interface{}{b, (r.SimHash >> (uint(b) * uint(blockBits))) & ((uint64(1) << blockBits) - 1)}
buckets[key] = append(buckets[key], shEntry{idx: i, hash: r.SimHash})
}
}

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
if results[i].BlockPage || results[i].SimHash == 0 || results[i].HashSource != "body" || (results[i].StatusCode >= 300 && results[i].StatusCode < 400) {
continue
}
root := find(i)
hosts := hostsByCluster[root]
if len(hosts) >= blockPageMinHosts ||
(len(hosts) >= 2 && urlsByCluster[root] >= blockPageMinURLs) ||
urlsByCluster[root] >= blockPageSingleHostDominance {
if !clusterLooksLikeBlock(results, hosts) {
continue
}
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
