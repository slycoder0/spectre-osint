<div align="center">

<p align="center">
  <img src="docs/assets/brand/spectre-banner.svg" alt="SPECTRE OSINT Banner" width="100%">
</p>

# SPECTRE OSINT

**Workstation de Inteligência Pública &bull; Passive-First &bull; Orientada a Evidências**

[🇧🇷 Português](#) &nbsp;|&nbsp; [🇺🇸 English](README.en.md)

[![Python](https://img.shields.io/badge/Python-3.12%20%7C%203.13-38bdf8?style=flat-square&logo=python&logoColor=white)](pyproject.toml)
[![License](https://img.shields.io/badge/Licen%C3%A7a-MIT-22d3ee?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Vers%C3%A3o-0.1.0b1%20Beta-0ea5e9?style=flat-square)](CHANGELOG.md)
[![Interface](https://img.shields.io/badge/Interface-CLI--First-0284c7?style=flat-square)](docs/commands.md)
[![Coleta](https://img.shields.io/badge/Coleta-Passive--First-0369a1?style=flat-square)](docs/concepts/privacy-and-safety.md)
[![Armazenamento](https://img.shields.io/badge/Armazenamento-Local%20(SQLite)-1e293b?style=flat-square)](docs/getting-started.md)
[![CI](https://github.com/slycoder0/spectre-osint/actions/workflows/ci.yml/badge.svg)](https://github.com/slycoder0/spectre-osint/actions/workflows/ci.yml)

<p align="center">
  O <strong>SPECTRE</strong> é uma ferramenta de linha de comando para mapear, estruturar e correlacionar pegadas digitais públicas a partir de usernames, domínios, e-mails e outros indicadores, registrando a origem de cada achado e evitando transformar suposições em fatos.
</p>

</div>

---

## 🎯 O que o SPECTRE faz

- **Mapeamento de Usernames:** Varre dezenas de plataformas públicas usando contratos estruturados (APIs JSON e assinaturas HTML) com validação estrutural de existência do perfil.
- **Inteligência de Busca & Descoberta:** Executa consultas dorking em motores de busca públicos, identifica perfis candidatos e descobre novos pivôs de investigação.
- **Correlação Conservadora de Identidades:** Avalia a convergência entre múltiplos perfis públicos utilizando pesos determinísticos e detecção de conflitos biográficos.
- **Sessões Públicas Autenticadas:** Permite observar metadados públicos em redes com login-wall (ex: Instagram) via perfis isolados do Chromium, sem coletar ou armazenar senhas.
- **Relatórios Locais & Grafos:** Gera relatórios detalhados em HTML de arquivo único (o grafo interativo carrega a biblioteca Cytoscape de `unpkg.com` ao abrir), JSON, Markdown, CSV e Grafos de Relacionamento (GraphML).

---

## ⚡ Início Rápido (Quick Start)

Instale e execute sua primeira investigação no terminal:

### 1. Clonar e configurar o ambiente

#### Windows (PowerShell)
```powershell
git clone https://github.com/slycoder0/spectre-osint.git
cd spectre-osint
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

#### Linux / macOS
```bash
git clone https://github.com/slycoder0/spectre-osint.git
cd spectre-osint
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. Verificar o ambiente

```bash
spectre doctor
```

### 3. Executar sua primeira investigação

```bash
spectre username alice_osint
```

Os resultados detalhados serão exibidos no terminal e salvos localmente na pasta `reports/`.

---

## 🧭 Comandos Essenciais

| Quero... | Comando | Descrição |
| :--- | :--- | :--- |
| **Diagnosticar instalação** | `spectre doctor` | Valida dependências, banco SQLite e providers sem expor chaves. |
| **Investigar username** | `spectre username <handle>` | Varredura de perfil público no catálogo com extração de metadados. |
| **Investigar e-mail** | `spectre email <email>` | Análise de formato, MX/DNS e presença pública. |
| **Investigar domínio** | `spectre domain <dominio>` | Inteligência DNS, RDAP, certificados CT e fingerprinting. |
| **Investigar endereço IP** | `spectre ip <ip>` | Inteligência de IP, geolocalização e histórico de rede. |
| **Investigação completa** | `spectre investigate <alvo>` | Pipeline completo com correlação, grafo e relatório HTML. |
| **Gerar relatórios** | `spectre report [caso]` | Regenera artefatos em HTML, JSON, Markdown ou GraphML. |
| **Sessões autenticadas** | `spectre auth status` | Exibe e gerencia sessões autenticadas para redes com login-wall. |
| **Status do cache** | `spectre cache status` | Exibe registros em cache local e tempo de expiração (TTL). |

👉 [Consulte a Referência Completa de Comandos](docs/commands.md)

---

## 🛡️ Como o SPECTRE evita falsos positivos

Diferente de scripts que consideram qualquer resposta HTTP 200 como um perfil válido, o SPECTRE aplica regras técnicas consistentes:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                      REGRAS DE CONTROLE PROBATÓRIO                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✖  HTTP 200 ≠ Perfil Confirmado       ✖  Mesmo Username ≠ Mesma Pessoa     │
│  ✖  Entrada do Analista ≠ Evidência    ✖  Candidato de Busca ≠ CONFIRMED    │
│  ✔  Proveniência Explícita de Origem   ✔  Correlação Conservadora de Perfis │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **HTTP 200 não confirma perfil:** A presença exige validação de campos escalares estruturais (IDs JSON) ou marcadores HTML específicos.
2. **Mesmo handle não prova a mesma pessoa:** O reuso de um username entre redes é um sinal de partida, nunca uma certeza de identidade civil.
3. **Pistas do analista não viram evidências da web:** Dados fornecidos pelo operador (`--name`, `--email`) ficam separados dos achados observados.
4. **Candidatos de busca permanecem candidatos:** Resultados de motores de busca são pistas para investigação, não perfis confirmados.

👉 [Leia o Modelo de Evidências Completo](docs/concepts/evidence.md) &bull; [Dicionário de Resultados & Status](docs/results.md)

---

## 📚 Central de Documentação

Acesse a documentação completa do SPECTRE OSINT:

- 🚀 [Guia de Início Rápido](docs/getting-started.md)
- 💻 [Guia de Instalação Detalhado](docs/installation.md)
- 📖 [Manual de Comandos CLI](docs/commands.md)
- 🔬 [Exemplos Práticos de Investigação](docs/examples.md)
- 📊 [Significado dos Status de Resultado](docs/results.md)
- 🧠 [Modelo de Evidências & Invariantes](docs/concepts/evidence.md)
- 🏗️ [Arquitetura Técnica & Site Catalog 2.0](docs/technical/architecture.md)
- 🔒 [Privacidade & Limites Operacionais](docs/concepts/privacy-and-safety.md)

---

## 🔒 Limites Operacionais & Segurança

- **Execução & Armazenamento Local:** Banco SQLite, logs e relatórios são salvos localmente no seu computador.
- **Passive-First:** Coleta somente informações públicas disponíveis na internet. O fluxo principal opera sem chaves pagas.
- **Zero Captura de Senhas:** O login autenticado é realizado manualmente pelo operador em janela visível; o SPECTRE nunca solicita ou armazena senhas.
- **Sem Evasão Hostil:** O software não resolve CAPTCHAs, não quebra autenticações e não manipula impressões digitais TLS.

---

## 👥 Contribuição & Licença

Contribuições são bem-vindas! Consulte as [Diretrizes de Contribuição](CONTRIBUTING.md) e o [Guia de Testes](docs/technical/testing.md).

Distribuído sob licença [MIT](LICENSE). Código-fonte aberto e auditável.

---

<div align="center">
  <sub>SPECTRE OSINT &bull; Inteligência pública com disciplina probatória e foco em CLI.</sub>
</div>
