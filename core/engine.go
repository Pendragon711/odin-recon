package core

import (
	"fmt"

	"odin/modules"
	"odin/utils"
)

// RunPipeline orquestra a execução de todas as fases do recon.
// Diferente da versão anterior, cada etapa persiste seu próprio resultado
// e uma falha parcial não derruba o restante do pipeline — só o scan
// final é marcado como 'failed' se uma etapa crítica (discovery/DNS) falhar.
func RunPipeline(domain string, cfg *Config) error {
	utils.LogInfo(fmt.Sprintf("Iniciando pipeline do ODIN para o alvo: %s (perfil: %s)", domain, cfg.Profile))

	scanID, err := StartScan(domain, cfg.Profile)
	if err != nil {
		return fmt.Errorf("falha ao registrar scan: %w", err)
	}

	scope := NewScope(cfg, domain)

	// 1. Descoberta de subdomínios (subfinder + bruteforce/permutação)
	discovered, err := modules.RunDiscovery(domain, modules.DiscoveryConfig{
		UseSubfinder: cfg.Discovery.UseSubfinder,
		Bruteforce:   cfg.Discovery.Bruteforce,
		Permutations: cfg.Discovery.Permutations,
		Wordlist:     cfg.Discovery.Wordlist,
	})
	if err != nil {
		FinishScan(scanID, "failed")
		return fmt.Errorf("falha no módulo de discovery: %w", err)
	}

	inScope := scope.FilterInScope(discovered.AllHosts())
	dropped := len(discovered.AllHosts()) - len(inScope)
	if dropped > 0 {
		utils.LogWarning(fmt.Sprintf("%d hosts descartados por estarem fora do escopo configurado.", dropped))
	}

	for source, hosts := range discovered.BySource {
		inScopeForSource := scope.FilterInScope(hosts)
		if err := SaveSubdomains(scanID, inScopeForSource, source); err != nil {
			utils.LogWarning(fmt.Sprintf("Falha ao salvar subdomínios de %s: %v", source, err))
		}
	}

	// 2. DNS: resolução completa + wildcard + AXFR
	dnsOpts := modules.DNSOptions{
		Resolvers:      cfg.DNS.Resolvers,
		RecordTypes:    cfg.DNS.RecordTypes,
		WildcardCheck:  cfg.DNS.WildcardCheck,
		TryAXFR:        cfg.DNS.TryAXFR,
		TimeoutSeconds: cfg.DNS.TimeoutSeconds,
		Concurrency:    cfg.DNS.Concurrency,
	}
	dnsResults, err := modules.RunDNSResolution(inScope, dnsOpts)
	if err != nil {
		FinishScan(scanID, "failed")
		return fmt.Errorf("falha no módulo de DNS: %w", err)
	}

	var dnsRows []DNSRecordRow
	var resolvedHosts []string
	hostToIP := make(map[string]string)
	for _, r := range dnsResults.Records {
		dnsRows = append(dnsRows, DNSRecordRow{
			Host: r.Host, RecordType: r.Type, Value: r.Value, IsWildcard: r.IsWildcard,
		})
	}
	for host, ips := range dnsResults.ResolvedA {
		if len(ips) == 0 {
			continue
		}
		resolvedHosts = append(resolvedHosts, host)
		hostToIP[host] = ips[0]
	}
	if err := SaveDNSRecords(scanID, dnsRows); err != nil {
		utils.LogWarning(fmt.Sprintf("Falha ao salvar registros DNS: %v", err))
	}

	// Retroalimentação: CNAMEs e NS descobertos que caem no escopo viram
	// novos candidatos a subdomínio, mesmo que não tenham sido achados
	// por nenhuma fonte de discovery.
	var feedbackHosts []string
	for _, r := range dnsResults.Records {
		if r.Type == "CNAME" || r.Type == "NS" {
			feedbackHosts = append(feedbackHosts, r.Value)
		}
	}
	feedbackInScope := scope.FilterInScope(feedbackHosts)
	if len(feedbackInScope) > 0 {
		SaveSubdomains(scanID, feedbackInScope, "dns_feedback")
		utils.LogInfo(fmt.Sprintf("%d hosts novos via retroalimentação de DNS (CNAME/NS).", len(feedbackInScope)))
	}

	// 3. Portas
	portResults, err := modules.RunPortScan(resolvedHosts, hostToIP, modules.PortScanOptions{
		Ports:     cfg.PortsForProfile(),
		Rate:      cfg.Ports.Rate,
		TimeoutMs: cfg.Ports.TimeoutMs,
	})
	if err != nil {
		utils.LogWarning(fmt.Sprintf("Falha no módulo de portas, continuando sem ele: %v", err))
	}
	var portRows []PortRow
	for _, p := range portResults {
		portRows = append(portRows, PortRow{Host: p.Subdomain, IP: p.IP, Port: p.Port})
	}
	if err := SavePorts(scanID, portRows); err != nil {
		utils.LogWarning(fmt.Sprintf("Falha ao salvar portas: %v", err))
	}

	// 4. HTTP probing (testa http e https, não adivinha pela porta).
	//    -fd (filter-duplicates) do httpx fica DESLIGADO: ele usa o mesmo
	//    simhash de corpo e descartaria silenciosamente clones legítimos
	//    antes da nossa contagem de hosts — a detecção de WAF precisa ver
	//    todas as respostas para contar repetições por host.
	httpResults, err := modules.RunHTTPProbing(portResults, modules.HTTPOptions{
		Threads:         cfg.HTTP.Threads,
		TimeoutSeconds:  cfg.HTTP.TimeoutSeconds,
		FollowRedirects: cfg.HTTP.FollowRedirects,
		GlobalRPS:       cfg.RateLimit.GlobalRPS,
		UserAgent:       cfg.HTTP.UserAgent,
	})
	if err != nil {
		utils.LogWarning(fmt.Sprintf("Falha no módulo HTTP, continuando sem ele: %v", err))
	}

	var httpRows []HTTPServiceRow
	var tlsFeedbackHosts []string
	for _, r := range httpResults {
		httpRows = append(httpRows, HTTPServiceRow{
			Host: r.Subdomain, IP: r.IP, Port: r.Port, Protocol: r.Protocol,
			StatusCode: r.StatusCode, Title: r.Title, Tech: r.Tech, URL: r.URL,
			ContentLength: r.ContentLength, BodyHash: r.BodyHash, SimHash: r.SimHash, FaviconHash: r.FaviconHash,
			Server: r.Server, CDN: r.CDNName, IsBlockPage: r.BlockPage, TLSSans: r.TLSSansJSON,
		})
		tlsFeedbackHosts = append(tlsFeedbackHosts, r.TLSSans...)
	}
	if err := SaveHTTPServices(scanID, httpRows); err != nil {
		utils.LogWarning(fmt.Sprintf("Falha ao salvar serviços HTTP: %v", err))
	}

	// Retroalimentação: SANs de certificado TLS que caiam no escopo.
	tlsInScope := scope.FilterInScope(tlsFeedbackHosts)
	if len(tlsInScope) > 0 {
		SaveSubdomains(scanID, tlsInScope, "tls_san")
		utils.LogInfo(fmt.Sprintf("%d hosts novos via SANs de certificado TLS.", len(tlsInScope)))
	}

	// 5. Crawler — agora o resultado é persistido de fato.
	if cfg.Crawler.Enabled {
		endpointResults, err := modules.RunCrawler(httpResults, modules.CrawlerOptions{
			MaxDepth:    cfg.Crawler.MaxDepth,
			Concurrency: cfg.Crawler.Concurrency,
			Parallelism: cfg.Crawler.Parallelism,
			RateLimit:   cfg.Crawler.RateLimit,
		})
		if err != nil {
			utils.LogWarning(fmt.Sprintf("Aviso no módulo de crawling: %v", err))
		}
		var endpointRows []EndpointRow
		var jsFeedbackHosts []string
		for _, e := range endpointResults {
			endpointRows = append(endpointRows, EndpointRow{
				SourceURL: e.SourceURL, Endpoint: e.Endpoint, Method: e.Method,
			})
			jsFeedbackHosts = append(jsFeedbackHosts, e.HostsFound...)
		}
		if err := SaveEndpoints(scanID, endpointRows); err != nil {
			utils.LogWarning(fmt.Sprintf("Falha ao salvar endpoints: %v", err))
		}

		jsInScope := scope.FilterInScope(jsFeedbackHosts)
		if len(jsInScope) > 0 {
			SaveSubdomains(scanID, jsInScope, "js")
			utils.LogInfo(fmt.Sprintf("%d hosts novos via extração de JS/links do crawler.", len(jsInScope)))
		}
	}

	FinishScan(scanID, "completed")
	utils.LogSuccess(fmt.Sprintf("Pipeline do ODIN finalizado para %s! (scan_id=%d)", domain, scanID))
	return nil
}
