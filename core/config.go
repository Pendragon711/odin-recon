package core

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ScopeConfig struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

type DNSConfig struct {
	Resolvers      []string `yaml:"resolvers"`
	WildcardCheck  bool     `yaml:"wildcard_check"`
	RecordTypes    []string `yaml:"record_types"`
	TryAXFR        bool     `yaml:"try_axfr"`
	TimeoutSeconds int      `yaml:"timeout_seconds"`
	Concurrency    int      `yaml:"concurrency"`
}

type DiscoveryConfig struct {
	UseSubfinder bool   `yaml:"use_subfinder"`
	Bruteforce   bool   `yaml:"bruteforce"`
	Wordlist     string `yaml:"wordlist"`
	Permutations bool   `yaml:"permutations"`
}

type PortsConfig struct {
	Profiles  map[string]string `yaml:"profiles"`
	Rate      int               `yaml:"rate"`
	TimeoutMs int               `yaml:"timeout_ms"`
}

type HTTPConfig struct {
	Threads         int    `yaml:"threads"`
	TimeoutSeconds  int    `yaml:"timeout_seconds"`
	FollowRedirects bool   `yaml:"follow_redirects"`
	Screenshot      bool   `yaml:"screenshot"`
	UserAgent       string `yaml:"user_agent"` // vazio = UA de navegador comum (o default do httpx se anuncia como scanner e convida WAF)
}

type CrawlerConfig struct {
	Enabled     bool `yaml:"enabled"`
	MaxDepth    int  `yaml:"max_depth"`
	Concurrency int  `yaml:"concurrency"`
	Parallelism int  `yaml:"parallelism"`
	RateLimit   int  `yaml:"rate_limit"`
	Headless    bool `yaml:"headless"`
	ScopeStrict bool `yaml:"scope_strict"`
}

type RateLimitConfig struct {
	GlobalRPS int `yaml:"global_rps"`
}

type OutputConfig struct {
	SaveJSON bool   `yaml:"save_json"`
	JSONPath string `yaml:"json_path"`
}

type Config struct {
	Profile   string          `yaml:"profile"`
	Scope     ScopeConfig     `yaml:"scope"`
	DNS       DNSConfig       `yaml:"dns"`
	Discovery DiscoveryConfig `yaml:"discovery"`
	Ports     PortsConfig     `yaml:"ports"`
	HTTP      HTTPConfig      `yaml:"http"`
	Crawler   CrawlerConfig   `yaml:"crawler"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	Output    OutputConfig    `yaml:"output"`
}

// defaultConfig é usado quando o config.yaml não existe ou falha ao ler,
// para o Odin nunca travar por falta de arquivo de configuração.
func defaultConfig() *Config {
	return &Config{
		Profile: "standard",
		Scope:   ScopeConfig{Include: []string{}, Exclude: []string{}},
		DNS: DNSConfig{
			Resolvers:      []string{"1.1.1.1", "8.8.8.8"},
			WildcardCheck:  true,
			RecordTypes:    []string{"A", "AAAA", "CNAME", "NS", "MX", "TXT"},
			TryAXFR:        true,
			TimeoutSeconds: 5,
			Concurrency:    50,
		},
		Discovery: DiscoveryConfig{UseSubfinder: true, Bruteforce: true, Permutations: true},
		Ports: PortsConfig{
			Profiles: map[string]string{
				"quick":    "80,443",
				"standard": "80,443,8000,8080,8443,8888,9000,9090,9443",
				"deep":     "top-1000",
			},
			Rate:      1000,
			TimeoutMs: 1000,
		},
		HTTP:      HTTPConfig{Threads: 25, TimeoutSeconds: 10, FollowRedirects: true},
		Crawler:   CrawlerConfig{Enabled: true, MaxDepth: 2, Concurrency: 10, Parallelism: 10, RateLimit: 150, ScopeStrict: true},
		RateLimit: RateLimitConfig{GlobalRPS: 50},
		Output:    OutputConfig{SaveJSON: true, JSONPath: "db/output"},
	}
}

// LoadConfig lê config.yaml do caminho informado. Se não existir, devolve defaults
// e um aviso (não é erro fatal — o Odin deve funcionar sem config.yaml).
func LoadConfig(path string) (*Config, bool, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, false, nil
		}
		return cfg, false, fmt.Errorf("erro ao ler %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return defaultConfig(), false, fmt.Errorf("erro ao parsear %s: %w", path, err)
	}

	if cfg.Ports.Profiles == nil || cfg.Ports.Profiles[cfg.Profile] == "" {
		def := defaultConfig()
		if cfg.Ports.Profiles == nil {
			cfg.Ports.Profiles = def.Ports.Profiles
		}
	}

	return cfg, true, nil
}

// PortsForProfile resolve a string de portas do perfil ativo.
func (c *Config) PortsForProfile() string {
	if p, ok := c.Ports.Profiles[c.Profile]; ok && p != "" {
		return p
	}
	return "80,443,8000,8080,8443,8888,9000,9090,9443"
}
