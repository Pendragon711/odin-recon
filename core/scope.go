package core

import "strings"

// Scope representa as regras de escopo carregadas do config.yaml
// mais o domínio raiz passado em -d, que sempre entra implicitamente.
type Scope struct {
	include []string
	exclude []string
}

func NewScope(cfg *Config, rootDomain string) *Scope {
	include := append([]string{}, cfg.Scope.Include...)
	// O domínio alvo da execução atual sempre está em escopo,
	// mesmo que o config.yaml não tenha sido ajustado.
	implicit := "*." + rootDomain
	found := false
	for _, inc := range include {
		if inc == implicit || inc == rootDomain {
			found = true
			break
		}
	}
	if !found {
		include = append(include, implicit, rootDomain)
	}

	return &Scope{
		include: include,
		exclude: cfg.Scope.Exclude,
	}
}

// Allowed verifica se um host está dentro do escopo configurado.
// Regra: precisa casar com pelo menos um include e com nenhum exclude.
func (s *Scope) Allowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}

	for _, ex := range s.exclude {
		if matchPattern(host, strings.ToLower(ex)) {
			return false
		}
	}

	for _, inc := range s.include {
		if matchPattern(host, strings.ToLower(inc)) {
			return true
		}
	}

	return false
}

// matchPattern suporta "*.dominio.com" (dominio.com e qualquer subdomínio)
// e correspondência exata.
func matchPattern(host, pattern string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return false
}

// FilterInScope devolve apenas os hosts dentro do escopo, descartando o resto.
func (s *Scope) FilterInScope(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		if s.Allowed(h) {
			out = append(out, h)
		}
	}
	return out
}
