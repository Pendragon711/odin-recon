package core

import "strings"

type Scope struct {
include []string
exclude []string
}

func NewScope(cfg *Config, rootDomain string) Scope {
include := append([]string{}, cfg.Scope.Include...)
implicit := "." + rootDomain
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
return Scope{
include: include,
exclude: cfg.Scope.Exclude,
}
}

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

func matchPattern(host, pattern string) bool {
if pattern == host {
return true
}
if strings.HasPrefix(pattern, ".") {
base := strings.TrimPrefix(pattern, ".")
return host == base || strings.HasSuffix(host, "."+base)
}
return false
}

func (s *Scope) FilterInScope(hosts []string) []string {
var out []string
for _, h := range hosts {
if s.Allowed(h) {
out = append(out, h)
}
}
return out
}


