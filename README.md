# Odin — Advanced Web Reconnaissance Pipeline

**Odin** é uma ferramenta de **Web Reconnaissance desenvolvida em Go** para Pentest e Red Team. Ela orquestra um pipeline modular de descoberta de ativos, resolução DNS, port scanning, HTTP probing e crawling, com mecanismos de detecção de WAF e isolamento dos dados por alvo.

> ⚠️ **Aviso legal:** o Odin deve ser utilizado exclusivamente em ativos para os quais você possui autorização para realizar testes. O usuário é responsável por suas ações e pelo uso da ferramenta.

---

## ✨ Características

* **Pipeline resiliente** — falhas parciais em uma etapa não interrompem todo o processo.
* **Descoberta de subdomínios** — enumeração passiva utilizando Subfinder.
* **DNS Resolution** — resolução de subdomínios, validação de hosts e detecção de Wildcard DNS.
* **Port Scanning** — descoberta de portas TCP utilizando Naabu.
* **HTTP Probing** — identificação de serviços HTTP/HTTPS, status codes, títulos e tecnologias.
* **Detecção de WAF** — identificação baseada em assinaturas e análise de similaridade.
* **Crawling** — descoberta de URLs e recursos através do Katana.
* **Feedback loop** — novos hosts encontrados durante o processo podem ser reinseridos no escopo.
* **Banco isolado por alvo** — cada domínio possui seu próprio banco SQLite.
* **Exportação limpa** — exporta URLs válidas sem resultados identificados como WAF ou blockpage.
* **Perfis de execução** — `quick`, `standard` e `deep`.
* **Sem APIs pagas** — utiliza ferramentas open source e fontes públicas.

---

## 🚀 Instalação

### Requisitos

* Go
* Git
* Subfinder
* Naabu
* HTTPx
* Katana

As ferramentas externas devem estar disponíveis no `PATH` do sistema.

🛠️ Guia de Instalação (Kali Linux):

1. Pré-requisitos
Antes de começar, certifique-se de que seu sistema está atualizado e possui as ferramentas base instaladas:

```powershell
sudo apt
```

2. Instalando as Dependências do Pipeline
O Odin foi projetado para manter o fluxo de reconhecimento simples:
O ODIN orquestra ferramentas externas. Para que o pipeline funcione corretamente, instale as seguintes ferramentas via go install ou gerenciador de pacotes:
```powershell
# Instalar Subfinder (Enumeração de Subdomínios)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Instalar Naabu (Varredura de Portas)
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Instalar HTTPX (Sondagem HTTP)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Instalar Katana (Crawler Web)
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```
Nota: Certifique-se de que o diretório $GOPATH/bin esteja adicionado ao seu PATH no arquivo ~/.bashrc:
export PATH=$PATH:$(go env GOPATH)/bin

3. Clonando e Compilando o ODIN:
   
```powershell
# Clonar o repositório
git clone https://github.com/Pendragon711/odin-recon.git
cd odin-recon

# Compilar o binário
go build -o odin .

# (Opcional) Instalar globalmente para usar de qualquer pasta
sudo cp odin /usr/local/bin/odin
```
4. Configurando o Arquivo de Perfis:
Copie o arquivo de exemplo para criar sua configuração inicial:

```powershell
cp config.yaml.example config.yaml
```
Edite o config.yaml para ajustar wordlists ou chaves de API se necessário. Por padrão, o ODIN já vem com perfis otimizados (quick, standard, deep).

5. Teste de Funcionamento
Execute um scan de teste para validar a instalação:
```powershell

odin -d scanme.nmap.org -profile quick
```
Se o banner aparecer e o pipeline iniciar, sua instalação foi concluída com sucesso! 🚀

---

# 📖 Uso
```text
Scan → Consulta → Exportação
```

## Flags disponíveis

| Flag       | Tipo     | Descrição                                                                                                                          |
| ---------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `-d`       | `string` | Define o domínio alvo do reconhecimento. Inicia o pipeline e cria automaticamente um banco SQLite isolado para o domínio em `db/`. |
| `-profile` | `string` | Define o nível de profundidade do scan. Opções: `quick`, `standard` e `deep`. Sobrescreve o perfil definido no `config.yaml`.      |
| `-list`    | `bool`   | Consulta os resultados já armazenados no banco do alvo. Não executa um novo scan. Deve ser utilizado com `-d`.                     |
| `-status`  | `int`    | Filtra os resultados exibidos pelo código HTTP. Use `0` para visualizar todos os resultados.                                       |
| `-export`  | `string` | Exporta URLs válidas que não foram marcadas como WAF ou blockpage para o arquivo especificado.                                     |

---

## 🎯 Perfis de Scan

### Quick

Focado em velocidade e cobertura inicial.

* Portas: `80`, `443`
* Descoberta passiva de subdomínios
* Crawling superficial
* Ideal para triagem inicial de grandes superfícies

**Tempo estimado:** 1–5 minutos.

```bash
odin -d alvo.com -profile quick
```

---

### Standard

Perfil recomendado para a maioria dos pentests.

Inclui:

* Portas administrativas comuns:

  * `8080`
  * `8443`
  * `3000`
  * `4443`
  * `9090`
* Permutação limitada de subdomínios
* Crawling com profundidade moderada

**Tempo estimado:** 5–20 minutos.

```bash
odin -d alvo.com -profile standard
```

---

### Deep

Perfil de maior cobertura.

Inclui:

* Top 1000 portas TCP
* Bruteforce extensivo de subdomínios
* Wordlists maiores
* Crawling profundo
* Múltiplas iterações

Recomendado para alvos menores quando uma cobertura mais ampla da superfície de ataque for necessária.

**Tempo estimado:** 20–60 minutos.

```bash
odin -d alvo.com -profile deep
```

---

# 💻 Exemplos Práticos

## Scan rápido

```bash
odin -d alvo.com -profile quick
```

## Scan padrão

```bash
odin -d alvo.com -profile standard
```

## Scan profundo

```bash
odin -d alvo.com -profile deep
```

## Consultar todos os resultados

Consulta os serviços HTTP descobertos anteriormente:

```bash
odin -list -d alvo.com
```

## Filtrar por código HTTP

Exibir somente respostas `403`:

```bash
odin -list -d alvo.com -status 403
```

Exibir somente respostas `200`:

```bash
odin -list -d alvo.com -status 200
```

Use `0` para visualizar todos os resultados:

```bash
odin -list -d alvo.com -status 0
```

## Exportar alvos limpos

Exportar URLs válidas para utilização posterior em ferramentas como Nuclei:

```bash
odin -d alvo.com -export alvos_limpos.txt
```

O arquivo resultante contém uma URL por linha:

```text
https://alvo.com
https://api.alvo.com
https://admin.alvo.com
```

---

# 🏗️ Arquitetura do Pipeline

O Odin executa as seguintes fases em sequência:

```text
                    ┌─────────────────────┐
                    │        ODIN         │
                    │ Web Recon Pipeline  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  01. Discovery      │
                    │     Subfinder       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  02. DNS Resolution │
                    │ Wildcard Detection  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  03. Port Scanning  │
                    │       Naabu         │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   04. HTTP Probing  │
                    │       HTTPX         │
                    │    WAF Detection    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    05. Crawling     │
                    │       Katana        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    SQLite / DB      │
                    │   Per Target        │
                    └─────────────────────┘
```

### 01 — Discovery

Enumeração passiva de subdomínios utilizando **Subfinder** e fontes públicas, incluindo:

* Certificate Transparency
* DNS Dumpster
* HackerTarget
* Outras fontes públicas suportadas pelo Subfinder

O resultado alimenta as etapas seguintes do pipeline.

---

### 02 — DNS Resolution

Validação dos subdomínios descobertos.

Responsabilidades:

* Resolução DNS
* Identificação de endereços IP
* Detecção de Wildcard DNS
* Eliminação de falsos positivos
* Validação dos hosts descobertos

---

### 03 — Port Scanning

Utiliza **Naabu** para identificar portas TCP abertas nos hosts validados.

O conjunto de portas depende do perfil:

| Perfil     | Portas                        |
| ---------- | ----------------------------- |
| `quick`    | `80`, `443`                   |
| `standard` | Portas administrativas comuns |
| `deep`     | Top 1000 TCP                  |

---

### 04 — HTTP Probing

Utiliza **HTTPX** para sondar os serviços encontrados.

O módulo coleta informações como:

* URL
* HTTP status code
* Page title
* Tecnologias
* Headers
* CDN/WAF
* Similaridade de respostas

A identificação de tecnologias utiliza informações obtidas através de headers e fingerprinting baseado em Wappalyzer.

---

### 05 — Crawling

Utiliza **Katana** para rastrear os hosts HTTP ativos.

O crawler pode descobrir:

* URLs internas
* URLs externas
* Endpoints
* Recursos adicionais
* Hosts referenciados em aplicações web

A profundidade do crawling varia conforme o perfil selecionado.

---

# 🔄 Feedback Loop

O Odin pode utilizar informações descobertas durante o pipeline para expandir a superfície de reconhecimento.

Fontes de novos ativos incluem:

* SANs de certificados TLS
* CNAMEs
* Hosts encontrados em JavaScript
* Recursos descobertos durante crawling

Fluxo conceitual:

```text
Discovery
    │
    ▼
DNS
    │
    ▼
HTTP
    │
    ▼
Crawler
    │
    ├── URLs
    ├── Hosts
    └── JavaScript references
             │
             ▼
       Novos ativos
             │
             ▼
      Scope Validation
             │
             ▼
          Recon
```

Esse mecanismo permite que o Odin encontre ativos que não estavam presentes na primeira etapa de descoberta.

---

# 🧠 Decisões Técnicas

## Por que Subfinder e não Amass?

O **Amass**, da OWASP, é uma ferramenta poderosa para OSINT e enumeração profunda de infraestrutura. Entretanto, em superfícies muito grandes pode gerar maior quantidade de ruído, consumir mais memória e exigir configuração adicional de fontes e API keys.

O **Subfinder** foi escolhido como ferramenta principal do Odin por oferecer uma boa relação entre:

* velocidade;
* cobertura;
* simplicidade;
* foco em superfície web;
* integração com o ecossistema ProjectDiscovery.

O Amass continua sendo útil para cenários de enumeração de infraestrutura mais profunda e pode ser utilizado separadamente antes de alimentar resultados adicionais ao Odin.

---

## Por que SQLite e não PostgreSQL?

O Odin utiliza **SQLite** porque o banco:

* é embutido;
* não necessita de servidor;
* possui configuração mínima;
* facilita a portabilidade;
* permite um banco independente por alvo.

Exemplo:

```text
db/
├── alvo1.com_recon.db
├── alvo2.com_recon.db
└── alvo3.com_recon.db
```

A separação por alvo reduz conflitos e facilita o gerenciamento dos resultados.

A pasta `db/` também pode ser copiada para outra máquina para transportar os resultados armazenados.

---

## Por que Go?

Go foi escolhido devido a características importantes para uma ferramenta de recon:

* compilação nativa;
* binário único;
* ausência de runtime externo;
* concorrência nativa com goroutines;
* bom desempenho;
* facilidade de distribuição;
* ecossistema maduro de ferramentas e bibliotecas de segurança.

O projeto também se integra diretamente com ferramentas do ecossistema **ProjectDiscovery**.

---

# 🗄️ Banco de Dados

Cada alvo possui seu próprio banco SQLite:

```text
db/
├── alvo.com_recon.db
├── api.alvo.com_recon.db
└── outro-alvo.com_recon.db
```

O banco é criado automaticamente quando o alvo é processado.

### Limpar os dados de um alvo

No PowerShell:

```powershell
Remove-Item db\alvo.com_recon.db
```

> ⚠️ A remoção do arquivo apaga os resultados armazenados para aquele alvo.

---

# 🔗 Workflow / Chaining

Os resultados exportados pelo Odin podem alimentar outras ferramentas utilizadas durante um assessment.

### Odin → Nuclei

Primeiro, exporte os alvos:

```bash
odin -d alvo.com -export alvos_limpos.txt
```

Depois:

```bash
nuclei -l alvos_limpos.txt -t cves/ -rate-limit 50
```

### Odin → FFUF

Os hosts encontrados também podem ser utilizados como base para fuzzing:

```bash
ffuf -w wordlist.txt -u https://alvo.com/FUZZ -mc 200,401,403 -t 50
```

### Odin → Wafw00f

Para análise adicional de WAF:

```bash
wafw00f -i alvos_limpos.txt
```

> As ferramentas acima são externas ao Odin. O objetivo do chaining é permitir que os resultados da fase de reconnaissance sejam utilizados em etapas posteriores do assessment.

---

# 📁 Estrutura do Projeto

```text
odin/
├── main.go              # Ponto de entrada, parsing de flags e orquestração
├── config.yaml          # Configuração de perfis e parâmetros
├── go.mod               # Dependências do Go
├── go.sum               # Checksums das dependências
│
├── core/
│   ├── banner.go        # Banner ASCII personalizado
│   ├── config.go        # Carregamento e parsing do config.yaml
│   └── db.go            # Inicialização e operações no SQLite
│
├── modules/
│   ├── 01_discovery.go  # Enumeração de subdomínios
│   ├── 02_dns.go        # Resolução DNS e wildcard
│   ├── 03_ports.go      # Varredura de portas
│   ├── 04_http.go       # HTTP probing e detecção de WAF
│   └── 05_crawler.go    # Crawling de URLs
│
├── utils/
│   ├── logger.go        # Sistema de logs formatados
│   └── helpers.go       # Funções auxiliares, SimHash etc.
│
├── db/                  # Bancos isolados por alvo
│   └── <alvo>_recon.db
│
└── README.md
```

---

# 🛠️ Tecnologias

Odin utiliza ferramentas e tecnologias do ecossistema de segurança:

* **Go**
* **Subfinder**
* **Naabu**
* **HTTPX**
* **Katana**
* **SQLite**
* **Wappalyzer**
* **SimHash**

---

# 🧩 Resiliência

O pipeline foi projetado para tolerar falhas parciais.

Uma falha em determinada etapa não precisa interromper todo o processo:

```text
Discovery ──► DNS ──► Ports ──► HTTP ──► Crawler
    ✓          ✓        ✗         ✓         ✓
                       │
                       └── falha isolada
```

Essa abordagem permite que os resultados válidos das demais etapas continuem sendo processados.

---

# ⚙️ Configuração

As configurações principais ficam em:

```text
config.yaml
```

Os perfis disponíveis são:

```text
quick
standard
deep
```

Exemplo de configuração:

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

### Principais parâmetros

| Configuração                      | Descrição                       | Exemplo    |
| --------------------------------- | ------------------------------- | ---------- |
| `profile`                         | Perfil de execução              | `standard` |
| `scope.include`                   | Hosts permitidos                | `[]`       |
| `scope.exclude`                   | Hosts excluídos                 | `[]`       |
| `dns.concurrency`                 | Concorrência DNS                | `500`      |
| `dns.record_types`                | Tipos de registros DNS          | `A`        |
| `discovery.max_permutation_seeds` | Limite de seeds para permutação | `200`      |
| `rate_limit.global_rps`           | Limite global de requisições/s  | `50`       |
| `crawler.enabled`                 | Habilita crawling               | `true`     |

Para remover o limite de seeds:

```yaml
discovery:
  max_permutation_seeds: -1
```

> ⚠️ Valores elevados de concorrência ou ausência de limites podem aumentar significativamente o volume de tráfego e o tempo de processamento.

---

# 🐛 Troubleshooting

## `database is locked`

Evite executar dois scans simultaneamente para o mesmo alvo.

```text
Scan A ──► alvo.com_recon.db
Scan B ──► alvo.com_recon.db
                 ↑
              conflito
```

Execute apenas um processo por alvo por vez.

---

## Scan muito lento

Experimente utilizar o perfil `quick`:

```bash
odin -d alvo.com -profile quick
```

Também é possível revisar a concorrência DNS no `config.yaml`.

---

## Muitos resultados relacionados a WAF

A sensibilidade da detecção pode ser ajustada no módulo HTTP, especialmente no parâmetro relacionado à identificação de blockpages:

```text
blockPageMinHosts
```

O parâmetro está relacionado ao módulo:

```text
modules/04_http.go
```

Ajuste conforme o comportamento observado nos alvos autorizados.

---

# 📌 Roadmap

Possíveis evoluções do projeto:

* [ ] Melhorias na classificação de WAF
* [ ] Novas estratégias de fingerprinting
* [ ] Dashboard para visualização dos resultados
* [ ] Exportação JSON/CSV
* [ ] Melhor gerenciamento de escopo
* [ ] Novas estratégias de descoberta
* [ ] Integração com novos crawlers
* [ ] Métricas de execução do pipeline

---

# ⚠️ Aviso Legal

O Odin foi desenvolvido exclusivamente para **fins educacionais e testes de intrusão autorizados**.

Utilize a ferramenta somente em:

* ativos próprios;
* ambientes de laboratório;
* programas de Bug Bounty dentro do escopo permitido;
* avaliações de segurança autorizadas;
* sistemas para os quais você possui autorização explícita.

O uso desta ferramenta contra sistemas sem autorização pode ser ilegal.

**Sempre obtenha autorização antes de realizar atividades de reconhecimento ou testes de segurança.**

O autor não se responsabiliza pelo uso indevido da ferramenta.

---

# 📜 Licença

Este projeto é distribuído sob a licença **MIT**.

Consulte o arquivo [`LICENSE`](LICENSE) para os termos completos.

Você pode usar, modificar e distribuir o projeto, desde que mantenha o aviso de copyright original e cumpra os termos da licença MIT.

---

# 👤 Autor

**Pendragon711**

Desenvolvedor e entusiasta de segurança ofensiva.

> *"Thought and Memory fly across the world."*
> — Huginn e Muninn, os corvos de Odin.

---

<p align="center">
  <strong>Odin — Advanced Web Reconnaissance Pipeline</strong>
  <br>
  <em>Reconnaissance · Attack Surface · Intelligence</em>
  <br><br>
  <strong>ᛟ Odin sees all ᛟ</strong>
</p>
