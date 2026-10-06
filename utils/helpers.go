package utils

import "strings"

func NormalizeHost(host string) string {
h := strings.ToLower(strings.TrimSpace(host))
h = strings.TrimSuffix(h, ".")
return h
}

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
