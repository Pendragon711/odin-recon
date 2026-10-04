package utils

import "strings"

// NormalizeHost deixa um host em formato canônico para evitar duplicatas
// por diferença de maiúsculas/minúsculas ou ponto final (FQDN).
func NormalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	return h
}

// Dedup remove duplicatas de uma lista de strings preservando a ordem
// de primeira ocorrência.
func Dedup(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, it := range items {
		if it == "" || seen[it] {
			continue
		}
		seen[it] = true
		out = append(out, it)
	}
	return out
}
