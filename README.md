Odin - Advanced Web Reconnaissance Pipeline
Ferramenta de RECON web em Go para Pentest e Red Team. Orquestra um pipeline modular de descoberta, DNS, portas, HTTP e crawling com detecao avancada de WAF e isolamento de dados por alvo.
AVISO LEGAL: Uso restrito a testes autorizados. O usuario e responsavel por suas acoes.
Caracteristicas
Pipeline resiliente: falhas parciais nao derrubam o scan inteiro
Detecao de WAF dupla camada: assinatura (keyword) + clusterizacao (simhash)
Feedback loop: SANs TLS, CNAMEs e hosts de JS reinjetados no escopo
Banco isolado por alvo: db/<alvo>_recon.db (sem conflito de concorrencia)
Exportacao limpa: -export gera lista de URLs sem ruido de WAF
Zero dependencia de APIs pagas

Arquitetura:

1.Discovery (01_discovery): Subfinder + bruteforce + permutacao
2.DNS (02_dns): Resolucao massiva + wildcard + AXFR
3.Portas (03_port): Naabu com IPs pre-resolvidos
4.HTTP (04_http): HTTPx com deteccao de WAF/Blockpage
5.Crawler (05_crawler): Katana com extracao de hosts em JS

Instalacao (PowerShell):
```bash
git clone https://github.com/seu-usuario/odin.git
cd odin
go mod tidy
go build -o odin.exe .
```
Uso:
```bash
# Scan rapido
.\odin.exe -d exemplo.com -profile quick

# Scan padrao
.\odin.exe -d exemplo.com -profile standard

# Listar resultados
.\odin.exe -list -d exemplo.com

# Filtrar por status
.\odin.exe -list -d exemplo.com -status 200

# Exportar alvos limpos (sem WAF)
.\odin.exe -d exemplo.com -export alvos.txt

# Limpar dados de um alvo
Remove-Item db\exemplo.com_recon.db
```
Configuracao (config.yaml):

Perfis: quick | standard | deep

Chaves principais:
profile: perfil ativo
scope.include / scope.exclude: controle de escopo
dns.concurrency: consultas simultaneas (500 recomendado)
dns.record_types: ["A"] no quick, todos no deep
discovery.max_permutation_seeds: 200 default, -1 sem teto
rate_limit.global_rps: teto de req/s (50 default)
crawler.enabled: true/false

Estrutura do Projeto:
```bash
Odin/
  main.go              CLI e ponto de entrada
  config.yaml          Configuracao
  core/                config, database, engine, scope
  modules/             01_discovery ate 05_crawler
  utils/               helpers, logger, ratelimit, simhash
  db/                  <alvo>_recon.db (bancos isolados)
```
  Fluxo de Trabalho (Chaining):
```bash
  # 1. Scan + export
  .\odin.exe -d ufms.br -profile standard -export alvos.txt
  
  # 2. Nuclei nos alvos limpos
  nuclei -l alvos.txt -t cves/ -rate-limit 50
  
  # 3. FFUF
  ffuf -w wordlist.txt -u FUZZ -mc 200,401,403 -t 50
  
  # 4. wafw00f (opcional)
  wafw00f -i alvos.txt
```
  Troubleshooting:

  database is locked: nao rode 2 scans no MESMO alvo simultaneamente
  scan lento: use -profile quick ou aumente dns.concurrency para 500
  go mod tidy falha: use go get github.com/projectdiscovery/httpx@latest
  muitos [[WAF?]] falsos: ajuste blockPageMinHosts em 04_http.go

  Tecnologias:
  Subfinder, Amass, DNSx, Naabu, HTTPx, Katana, SQLite (modernc.org/sqlite)

  Licenca:
  MIT. Veja LICENSE.

  Desenvolvido com foco em precisao, desempenho, stealth e etica profissional.
