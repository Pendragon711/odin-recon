# Odin — Advanced Web Reconnaissance Pipeline

**Odin** é uma ferramenta de **Web Reconnaissance desenvolvida em Go** para Pentest e Red Team. Ela orquestra um pipeline modular de descoberta de ativos, DNS, portas, HTTP e crawling, com detecção avançada de WAF e isolamento de dados por alvo.

> ⚠️ **Aviso legal:** o Odin deve ser utilizado exclusivamente em ativos para os quais você possui autorização para realizar testes. O usuário é integralmente responsável pelo uso da ferramenta e por suas ações.

---

## ✨ Características

* **Pipeline resiliente** — falhas parciais em módulos não interrompem o scan completo.
* **Detecção de WAF em duas camadas** — análise por assinatura/keywords e clusterização utilizando SimHash.
* **Feedback loop** — SANs de certificados TLS, CNAMEs e hosts encontrados em arquivos JavaScript podem ser reinjetados automaticamente no escopo.
* **Banco isolado por alvo** — cada domínio possui seu próprio banco SQLite, reduzindo conflitos entre scans.
* **Exportação limpa** — exporta URLs válidas removendo ruído causado por páginas de bloqueio/WAF.
* **Controle de escopo** — permite definir hosts incluídos e excluídos durante o processo de recon.
* **Perfis de execução** — `quick`, `standard` e `deep`.
* **Rate limiting global** — controle da quantidade de requisições por segundo.
* **Sem APIs pagas** — utiliza ferramentas open source e fontes públicas de descoberta.

---

## 🏗️ Arquitetura

O Odin organiza o processo de reconhecimento em módulos independentes:

```text
┌─────────────────────────────────────────────┐
│                    ODIN                     │
│        Advanced Web Reconnaissance          │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  01 Discovery   │
              │ Subfinder       │
              │ Bruteforce      │
              │ Permutation     │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │     02 DNS      │
              │ Resolution      │
              │ Wildcard        │
              │ AXFR            │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │    03 Ports     │
              │     Naabu       │
              │  Pre-resolved   │
              │      IPs        │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │    04 HTTP      │
              │     HTTPx       │
              │  WAF Detection  │
              │   Blockpages    │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   05 Crawler    │
              │     Katana      │
              │  JS Host Extract │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ SQLite Database │
              │  Per Target     │
              └─────────────────┘
```

### Pipeline

| Etapa | Módulo    | Função                                       |
| ----- | --------- | -------------------------------------------- |
| 01    | Discovery | Descoberta de subdomínios e hosts            |
| 02    | DNS       | Resolução, wildcard detection e AXFR         |
| 03    | Ports     | Descoberta de portas com Naabu               |
| 04    | HTTP      | Probing HTTP/HTTPS e detecção de WAF         |
| 05    | Crawler   | Crawling e descoberta de hosts em JavaScript |

---

## 🔍 Módulos

### 01 — Discovery

Responsável pela descoberta inicial de ativos.

Utiliza:

* Subfinder
* DNS bruteforce
* Permutação de subdomínios

O módulo também suporta limitação do número de seeds utilizados para geração de permutações.

---

### 02 — DNS

Executa resolução DNS em massa e valida informações relacionadas ao domínio.

Recursos:

* Resolução de registros DNS
* Detecção de wildcard DNS
* Identificação de registros CNAME
* Tentativa de AXFR
* Concorrência configurável

---

### 03 — Port Scan

Utiliza **Naabu** para descoberta de portas nos IPs previamente resolvidos.

O fluxo evita resolução DNS redundante:

```text
Hosts descobertos
       │
       ▼
   DNS Resolution
       │
       ▼
      IPs
       │
       ▼
     Naabu
       │
       ▼
 Open Ports
```

---

### 04 — HTTP

Executa probing HTTP/HTTPS utilizando **HTTPx**.

Além da identificação dos serviços HTTP, o módulo possui mecanismos para detectar:

* WAF
* Blockpages
* Respostas anômalas
* Assinaturas conhecidas
* Padrões semelhantes utilizando SimHash

A detecção utiliza duas camadas:

```text
HTTP Response
      │
      ├──► Keyword / Signature Detection
      │
      └──► SimHash Clustering
                │
                ▼
          WAF / Blockpage
```

---

### 05 — Crawler

Utiliza **Katana** para crawling dos endpoints encontrados.

Além da descoberta de URLs, o módulo pode extrair hosts encontrados em arquivos JavaScript e reinjetá-los no pipeline de reconhecimento.

Isso cria um **feedback loop**:

```text
Recon
  │
  ▼
HTTP
  │
  ▼
Crawler
  │
  ├──► URLs
  ├──► Hosts
  └──► JS references
          │
          ▼
     Scope Expansion
          │
          ▼
        Recon
```

---

## 🔄 Feedback Loop

O Odin pode ampliar dinamicamente o conjunto de ativos descobertos durante o scan.

Fontes utilizadas:

* SANs de certificados TLS
* CNAMEs
* Hosts encontrados em JavaScript

Exemplo:

```text
example.com
    │
    ├── api.example.com
    ├── dev.example.com
    └── www.example.com
             │
             ▼
        HTTP/Crawler
             │
             ├── api-internal.example.com
             └── cdn.example.com
                       │
                       ▼
                  Novo escopo
```

Os novos hosts passam novamente pelo pipeline quando considerados dentro das regras de escopo configuradas.

---

## 📦 Requisitos

### Software

* Go
* Git
* Subfinder
* Naabu
* HTTPx
* Katana

Dependendo da configuração utilizada, ferramentas adicionais de DNS/reconhecimento podem ser necessárias.

---

## 🚀 Instalação

### Windows — PowerShell

Clone o repositório:

```powershell
git clone https://github.com/seu-usuario/odin.git
cd odin
```

Instale as dependências:

```powershell
go mod tidy
```

Compile:

```powershell
go build -o odin.exe .
```

O executável será criado como:

```text
odin.exe
```

---

## ⚡ Uso

### Scan rápido

```powershell
.\odin.exe -d exemplo.com -profile quick
```

### Scan padrão

```powershell
.\odin.exe -d exemplo.com -profile standard
```

### Scan profundo

```powershell
.\odin.exe -d exemplo.com -profile deep
```

---

## 📊 Visualização dos resultados

Listar todos os resultados de um alvo:

```powershell
.\odin.exe -list -d exemplo.com
```

Filtrar por código HTTP:

```powershell
.\odin.exe -list -d exemplo.com -status 200
```

---

## 📤 Exportação

Exportar os alvos HTTP identificados, removendo resultados considerados ruído de WAF:

```powershell
.\odin.exe -d exemplo.com -export alvos.txt
```

O arquivo gerado pode ser utilizado como entrada para outras ferramentas de segurança.

Exemplo:

```text
https://example.com
https://api.example.com
https://dev.example.com
```

---

## 🗄️ Banco de Dados

Cada alvo possui um banco SQLite independente:

```text
db/
├── exemplo.com_recon.db
├── target.com_recon.db
└── outro-alvo.com_recon.db
```

Esse modelo reduz conflitos entre diferentes alvos e facilita o gerenciamento dos resultados.

### Remover os dados de um alvo

No PowerShell:

```powershell
Remove-Item db\exemplo.com_recon.db
```

> ⚠️ A remoção do banco apaga os resultados armazenados para aquele alvo.

---

## ⚙️ Configuração

As configurações principais ficam em:

```text
config.yaml
```

### Perfis

Odin possui três perfis:

```text
quick
standard
deep
```

### Exemplo

```yaml
profile: standard

scope:
  include: []
  exclude: []

dns:
  concurrency: 500
  record_types:
    - A

discovery:
  max_permutation_seeds: 200

rate_limit:
  global_rps: 50

crawler:
  enabled: true
```

---

## 🔧 Principais configurações

| Configuração                      | Descrição                       |     Padrão |
| --------------------------------- | ------------------------------- | ---------: |
| `profile`                         | Perfil de execução              | `standard` |
| `scope.include`                   | Hosts permitidos no escopo      |       `[]` |
| `scope.exclude`                   | Hosts excluídos do escopo       |       `[]` |
| `dns.concurrency`                 | Consultas DNS simultâneas       |      `500` |
| `dns.record_types`                | Tipos de registros consultados  |        `A` |
| `discovery.max_permutation_seeds` | Limite de seeds para permutação |      `200` |
| `rate_limit.global_rps`           | Limite global de requisições/s  |       `50` |
| `crawler.enabled`                 | Habilita/desabilita crawling    |     `true` |

### Permutações sem limite

Para remover o limite de seeds:

```yaml
discovery:
  max_permutation_seeds: -1
```

> ⚠️ Valores muito altos podem aumentar significativamente o volume de requisições e o tempo de execução.

---

## 🔗 Workflow / Chaining

O Odin foi projetado para funcionar como parte de um pipeline maior de segurança.

### 1. Recon + exportação

```powershell
.\odin.exe -d ufms.br -profile standard -export alvos.txt
```

### 2. Vulnerability scanning

Os alvos exportados podem ser utilizados como entrada para ferramentas como Nuclei:

```bash
nuclei -l alvos.txt -t cves/ -rate-limit 50
```

### 3. Fuzzing

Exemplo utilizando FFUF:

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -mc 200,401,403 -t 50
```

### 4. Detecção adicional de WAF

Opcionalmente:

```bash
wafw00f -i alvos.txt
```

> Essas ferramentas são etapas externas ao Odin. O objetivo do chaining é permitir que os resultados do reconhecimento sejam utilizados em outras fases do assessment.

---

## 📁 Estrutura do Projeto

```text
Odin/
├── main.go
├── config.yaml
├── core/
│   ├── config/
│   ├── database/
│   ├── engine/
│   └── scope/
├── modules/
│   ├── 01_discovery/
│   ├── 02_dns/
│   ├── 03_port/
│   ├── 04_http/
│   └── 05_crawler/
├── utils/
│   ├── helpers/
│   ├── logger/
│   ├── ratelimit/
│   └── simhash/
├── db/
│   └── <target>_recon.db
├── go.mod
├── go.sum
├── LICENSE
└── README.md
```

---

## 🛠️ Tecnologias

Odin utiliza ferramentas e bibliotecas do ecossistema de segurança e Go:

* **Go**
* **Subfinder**
* **Amass**
* **DNSx**
* **Naabu**
* **HTTPx**
* **Katana**
* **SQLite**
* **modernc.org/sqlite**

---

## 🧠 Resiliência

O pipeline foi projetado para tolerar falhas individuais.

Em vez de interromper todo o processo quando um módulo apresenta erro:

```text
Discovery ──► DNS ──► Ports ──► HTTP ──► Crawler
    ✓          ✓        ✗         ✓         ✓
                         │
                         └── falha isolada
```

Os demais módulos podem continuar processando os dados disponíveis.

---

## 🐛 Troubleshooting

### `database is locked`

Não execute dois scans simultaneamente para o mesmo alvo.

```text
Scan A ──► exemplo.com_recon.db
Scan B ──► exemplo.com_recon.db
             ↑
          conflito
```

Execute scans diferentes ou aguarde o primeiro processo terminar.

---

### Scan muito lento

Utilize o perfil rápido:

```powershell
.\odin.exe -d exemplo.com -profile quick
```

Ou ajuste a concorrência DNS:

```yaml
dns:
  concurrency: 500
```

> Aumentar concorrência nem sempre resulta em maior velocidade. O desempenho também depende de rede, DNS, rate limiting e comportamento dos alvos.

---

### `go mod tidy` falha

Atualize a dependência correspondente:

```powershell
go get github.com/projectdiscovery/httpx@latest
```

Depois:

```powershell
go mod tidy
```

---

### Muitos resultados `[[WAF?]]`

Ajuste o parâmetro de sensibilidade relacionado à detecção de blockpages no módulo:

```text
modules/04_http/
```

Procure pela configuração:

```text
blockPageMinHosts
```

Ajuste o valor conforme o comportamento observado nos alvos.

---

## 📌 Roadmap

Possíveis evoluções do projeto:

* [ ] Melhorias na classificação de WAF
* [ ] Novas estratégias de fingerprinting
* [ ] Dashboard para visualização dos resultados
* [ ] Exportação JSON/CSV
* [ ] Melhor gerenciamento de escopo
* [ ] Mais estratégias de descoberta
* [ ] Integração com novos crawlers
* [ ] Métricas de execução do pipeline

---

## ⚠️ Uso Responsável

O Odin é uma ferramenta de segurança destinada a **testes autorizados**.

Utilize-o somente em:

* ativos próprios;
* ambientes de laboratório;
* programas de Bug Bounty dentro do escopo permitido;
* avaliações de segurança autorizadas;
* ambientes onde você possui autorização explícita.

O desenvolvedor e os contribuidores não são responsáveis por danos causados pelo uso indevido da ferramenta.

---

## 📄 Licença

Este projeto está disponível sob a licença **MIT**.

Consulte o arquivo [`LICENSE`](LICENSE) para obter os termos completos.

---

## 👤 Autor

Desenvolvido com foco em:

**Precisão · Performance · Modularidade · Automação · Segurança**

> **[ Odin sees all ]**
