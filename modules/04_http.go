package modules

import (
	"encoding/json"
	"fmt"
	"os"

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
	FaviconHash   string
	Server        string
	TLSSans       []string // hosts extraídos do certificado, para retroalimentação
	TLSSansJSON   string   // mesmo conteúdo serializado, para gravar no banco
}

type HTTPOptions struct {
	Threads         int
	TimeoutSeconds  int
	FollowRedirects bool
}

// RunHTTPProbing testa cada host:porta descoberto sem assumir o esquema
// pela porta — o próprio httpx decide http vs https pela resposta real,
// o que evita falsos negativos em portas não-padrão com TLS.
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
		// Sem esquema: deixa o httpx testar https primeiro e cair para
		// http, em vez de adivinhar pela porta (8080/9000 com TLS, por
		// exemplo, eram perdidos na versão anterior).
		target := fmt.Sprintf("%s:%d", res.Subdomain, res.Port)
		targetMap[target] = res
		tmpFile.WriteString(target + "\n")
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
		Methods:         "GET",
		InputFile:       tmpFile.Name(),
		StatusCode:      true,
		TechDetect:      true,
		ExtractTitle:    true,
		OutputServerHeader: true,
		Hashes:          "mmh3", // favicon hash em mmh3, body hash também disponível via runner.Result
		FollowRedirects: opts.FollowRedirects,
		Threads:         threads,
		Timeout:         timeout,
		TLSGrab:         true, // necessário para popular r.TLSData com os SANs
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
			faviconHash := ""
			if r.Hashes != nil {
				if v, ok := r.Hashes["body_mmh3"]; ok {
					bodyHash = fmt.Sprintf("%v", v)
				}
				if v, ok := r.Hashes["favicon_mmh3"]; ok {
					faviconHash = fmt.Sprintf("%v", v)
				}
			}

			results = append(results, HTTPResult{
				Subdomain:     origInfo.Subdomain,
				IP:            origInfo.IP,
				Port:          origInfo.Port,
				Protocol:      r.Scheme,
				StatusCode:    r.StatusCode,
				Tech:          techStr,
				Title:         r.Title,
				URL:           r.URL,
				ContentLength: r.ContentLength,
				BodyHash:      bodyHash,
				FaviconHash:   faviconHash,
				Server:        r.WebServer,
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

	utils.LogSuccess(fmt.Sprintf("Sondagem HTTP concluída: %d aplicações web respondendo.", len(results)))
	return results, nil
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
