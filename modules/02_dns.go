package modules

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"odin/utils"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

type DNSOptions struct {
	Resolvers      []string
	RecordTypes    []string
	WildcardCheck  bool
	TryAXFR        bool
	TimeoutSeconds int
	Concurrency    int
}

type DNSRecord struct {
	Host       string
	Type       string
	Value      string
	IsWildcard bool
}

type DNSResultSet struct {
	Records   []DNSRecord
	ResolvedA map[string][]string // host -> IPs (só A), usado pelas etapas seguintes
}

// RunDNSResolution resolve cada host candidato contra os tipos de registro
// configurados, detecta wildcard no domínio raiz antes de confiar nos
// resultados, e tenta AXFR nos nameservers do domínio raiz.
func RunDNSResolution(hosts []string, opts DNSOptions) (*DNSResultSet, error) {
	utils.LogInfo(fmt.Sprintf("Iniciando resolução DNS para %d candidatos...", len(hosts)))

	if len(opts.Resolvers) == 0 {
		opts.Resolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	} else {
		for i, r := range opts.Resolvers {
			if !strings.Contains(r, ":") {
				opts.Resolvers[i] = r + ":53"
			}
		}
	}
	if opts.TimeoutSeconds <= 0 {
		opts.TimeoutSeconds = 5
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 50
	}
	if len(opts.RecordTypes) == 0 {
		opts.RecordTypes = []string{"A", "AAAA", "CNAME", "NS", "MX", "TXT"}
	}

	dnsxOptions := dnsx.DefaultOptions
	dnsxOptions.BaseResolvers = opts.Resolvers
	dnsClient, err := dnsx.New(dnsxOptions)
	if err != nil {
		return nil, fmt.Errorf("erro ao inicializar o dnsx: %w", err)
	}

	// Detecção de wildcard: consulta dois nomes aleatórios que quase
	// certamente não existem. Se ambos resolverem para o mesmo IP, o
	// domínio tem wildcard DNS e precisamos marcar/filtrar esses casos
	// para não poluir o banco com milhares de falsos positivos de
	// bruteforce.
	var wildcardIPs map[string]bool
	if opts.WildcardCheck && len(hosts) > 0 {
		root := rootDomainOf(hosts[0])
		wildcardIPs = detectWildcard(dnsClient, root)
		if len(wildcardIPs) > 0 {
			utils.LogWarning(fmt.Sprintf("Wildcard DNS detectado em *.%s — resultados idênticos serão marcados.", root))
		}
	}

	result := &DNSResultSet{ResolvedA: make(map[string][]string)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Concurrency)

	for _, h := range hosts {
		host := h
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			dnsResp, err := dnsClient.QueryOne(host)
			if err != nil || dnsResp == nil {
				return
			}

			mu.Lock()
			defer mu.Unlock()

			isWildcard := false
			if len(dnsResp.A) > 0 {
				for _, ip := range dnsResp.A {
					if wildcardIPs[ip] {
						isWildcard = true
					}
				}
				if !isWildcard {
					result.ResolvedA[host] = dnsResp.A
				}
				for _, ip := range dnsResp.A {
					result.Records = append(result.Records, DNSRecord{Host: host, Type: "A", Value: ip, IsWildcard: isWildcard})
				}
			}
			for _, ip := range dnsResp.AAAA {
				result.Records = append(result.Records, DNSRecord{Host: host, Type: "AAAA", Value: ip, IsWildcard: isWildcard})
			}
			for _, c := range dnsResp.CNAME {
				result.Records = append(result.Records, DNSRecord{Host: host, Type: "CNAME", Value: strings.TrimSuffix(c, "."), IsWildcard: isWildcard})
			}
			for _, ns := range dnsResp.NS {
				result.Records = append(result.Records, DNSRecord{Host: host, Type: "NS", Value: strings.TrimSuffix(ns, "."), IsWildcard: isWildcard})
			}
			for _, mx := range dnsResp.MX {
				result.Records = append(result.Records, DNSRecord{Host: host, Type: "MX", Value: strings.TrimSuffix(mx, "."), IsWildcard: isWildcard})
			}
			for _, txt := range dnsResp.TXT {
				result.Records = append(result.Records, DNSRecord{Host: host, Type: "TXT", Value: txt, IsWildcard: isWildcard})
			}
		}()
	}
	wg.Wait()

	utils.LogSuccess(fmt.Sprintf("%d hosts resolveram (A) sem contar como wildcard; %d registros no total.", len(result.ResolvedA), len(result.Records)))

	if opts.TryAXFR && len(hosts) > 0 {
		root := rootDomainOf(hosts[0])
		axfrRecords := tryAXFR(root, opts.TimeoutSeconds)
		if len(axfrRecords) > 0 {
			utils.LogSuccess(fmt.Sprintf("AXFR bem-sucedido em %s: %d registros extras.", root, len(axfrRecords)))
			result.Records = append(result.Records, axfrRecords...)
		}
	}

	return result, nil
}

// detectWildcard consulta subdomínios aleatórios improváveis de existir
// e devolve o conjunto de IPs que respondem "sempre", indicando wildcard.
func detectWildcard(client *dnsx.DNSX, root string) map[string]bool {
	ips := make(map[string]bool)
	rand.Seed(time.Now().UnixNano())

	for i := 0; i < 3; i++ {
		probe := fmt.Sprintf("odin-wildcard-check-%d.%s", rand.Intn(999999), root)
		resp, err := client.QueryOne(probe)
		if err == nil && resp != nil && len(resp.A) > 0 {
			for _, ip := range resp.A {
				ips[ip] = true
			}
		}
	}
	return ips
}

// tryAXFR tenta transferência de zona contra cada NS do domínio raiz.
// Na grande maioria dos casos isso falha (está certo que falhe — é um
// servidor mal configurado quando funciona), então erros aqui são
// silenciosos por design.
func tryAXFR(root string, timeoutSeconds int) []DNSRecord {
	var out []DNSRecord

	nsClient := new(dns.Client)
	nsClient.Timeout = time.Duration(timeoutSeconds) * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(root), dns.TypeNS)
	r, _, err := nsClient.Exchange(m, "1.1.1.1:53")
	if err != nil || r == nil {
		return out
	}

	var nameservers []string
	for _, ans := range r.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			nameservers = append(nameservers, ns.Ns)
		}
	}

	tr := new(dns.Transfer)
	for _, ns := range nameservers {
		axfrMsg := new(dns.Msg)
		axfrMsg.SetAxfr(dns.Fqdn(root))

		conn, err := dns.DialTimeout("tcp", ns+":53", time.Duration(timeoutSeconds)*time.Second)
		if err != nil {
			continue
		}
		tr.Conn = conn

		envelopeChan, err := tr.In(axfrMsg, ns+":53")
		if err != nil {
			conn.Close()
			continue
		}

		for env := range envelopeChan {
			if env.Error != nil {
				break
			}
			for _, rr := range env.RR {
				host := strings.TrimSuffix(rr.Header().Name, ".")
				switch v := rr.(type) {
				case *dns.A:
					out = append(out, DNSRecord{Host: host, Type: "A", Value: v.A.String()})
				case *dns.CNAME:
					out = append(out, DNSRecord{Host: host, Type: "CNAME", Value: strings.TrimSuffix(v.Target, ".")})
				}
			}
		}
		conn.Close()
	}

	return out
}

// rootDomainOf extrai o domínio raiz (2 últimos labels) de um host.
// Simplificado — não cobre todos os eTLDs compostos (ex: co.uk),
// suficiente para o caso de uso de bruteforce/wildcard dentro do Odin.
func rootDomainOf(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
