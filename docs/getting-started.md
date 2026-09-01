# Guia de Início Rápido

Este guia orienta a instalação do **SPECTRE OSINT** e a execução da sua primeira investigação no terminal.

---

## 1. Pré-requisitos

- **Python 3.12** ou **Python 3.13** instalado.
- **Git** instalado.

---

## 2. Instalação Passo a Passo

### Passo 1: Clonar o Repositório

```bash
git clone https://github.com/slycoder0/spectre-osint.git
cd spectre-osint
```

### Passo 2: Criar e Ativar o Ambiente Virtual

=== "Linux / macOS"
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

=== "Windows (PowerShell)"
    ```powershell
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    ```

### Passo 3: Instalar o Pacote em Modo Editável

```bash
pip install -e .
```

---

## 3. Verificação de Diagnóstico: `spectre doctor`

Antes de iniciar investigações, execute o comando de diagnóstico. Ele valida a instalação, permissões de pastas locais e integrações **sem iniciar investigações e sem imprimir segredos**:

```bash
spectre doctor
```

Exemplo de saída esperada:

```text
SPECTRE DOCTOR

Core
  Python                   3.13.x           OK
  SPECTRE                  0.1.0b1          OK
  Package import           OK               OK
  Database                 SQLite           OK
  Database writable        OK               OK
  Reports directory        OK               OK

Browser
  Chrome/Chromium          detected         OK

Security
  Bind address             127.0.0.1        OK
  Secrets redaction        OK               OK
  SSRF policy              enabled          OK

Overall: READY WITH OPTIONAL FEATURES MISSING
```

---

## 4. Primeira Investigação de Username

Execute uma varredura de perfil público no catálogo de plataformas:

```bash
spectre username alice_osint
```

### O que o comando faz:
1. Consulta dezenas de plataformas públicas catalogadas em `sites.yaml`.
2. Valida contratos de resposta (APIs JSON e assinaturas HTML de precisão).
3. Extrai metadados públicos observados (nome de exibição, biografia, avatar, localização e links externos) com proveniência estrita.
4. Salva o resultado no banco SQLite e os relatórios na pasta local `reports/`.

---

## 5. Investigação com Pistas do Operador

```bash
spectre investigate alice_osint \
  --name "Alice Example" \
  --email alice@example.com \
  --website "https://alice.example"
```

---

## 6. Onde os Resultados Ficam Salvos?

- **Relatórios HTML:** Pasta local `reports/` (exemplo: `reports/case-username-alice_osint-....html`).
- **Banco de Dados SQLite:** Armazenado em `data/spectre.db`.
- **Exportação:** Gere relatórios a qualquer momento com `spectre report`.
