# Guia Detalhado de Instalação

O **SPECTRE OSINT** é distribuído como um pacote Python moderno, compatível com Windows, Linux e macOS.

---

## Requisitos do Sistema

- **Python:** 3.12 ou 3.13 (definido em `pyproject.toml`)
- **Git** instalado no sistema

---

## Instalação Padrão

=== "Windows (PowerShell)"
    ```powershell
    # 1. Clone o repositório
    git clone https://github.com/slycoder0/spectre-osint.git
    cd spectre-osint

    # 2. Crie e ative o ambiente virtual
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1

    # 3. Instale o pacote base em modo editável
    pip install -e .

    # 4. Verifique a instalação
    spectre doctor
    ```

=== "Debian / Ubuntu / Kali"
    ```bash
    # 1. Instale dependências do sistema
    sudo apt update && sudo apt install -y python3-venv python3-pip git

    # 2. Clone o repositório
    git clone https://github.com/slycoder0/spectre-osint.git
    cd spectre-osint

    # 3. Crie e ative o ambiente virtual
    python3 -m venv .venv
    source .venv/bin/activate

    # 4. Instale o pacote base em modo editável
    pip install -e .

    # 5. Verifique a instalação
    spectre doctor
    ```

=== "Arch Linux"
    ```bash
    # 1. Instale dependências do sistema
    sudo pacman -Syu --needed python python-pip git

    # 2. Clone o repositório
    git clone https://github.com/slycoder0/spectre-osint.git
    cd spectre-osint

    # 3. Crie e ative o ambiente virtual
    python3 -m venv .venv
    source .venv/bin/activate

    # 4. Instale o pacote base em modo editável
    pip install -e .

    # 5. Verifique a instalação
    spectre doctor
    ```

=== "macOS"
    ```bash
    # 1. Clone o repositório
    git clone https://github.com/slycoder0/spectre-osint.git
    cd spectre-osint

    # 2. Crie e ative o ambiente virtual
    python3 -m venv .venv
    source .venv/bin/activate

    # 3. Instale o pacote base em modo editável
    pip install -e .

    # 4. Verifique a instalação
    spectre doctor
    ```

---

## Dependências Opcionais

### Pacote de Desenvolvimento e Testes (`dev`)
Inclui `pytest`, `ruff`, `mypy`, `pip-audit` e tipagens:
```bash
pip install -e ".[dev]"
```

### Pacote de Documentação Local (`docs`)
Inclui `mkdocs`, `mkdocs-material` e extensões:
```bash
pip install -e ".[docs]"
```

---

## Configuração Opcional do Arquivo `.env`

O fluxo principal do SPECTRE funciona sem chaves pagas. Para habilitar integrações opcionais de Threat Intelligence ou aumentar limites de quota:

```bash
cp .env.example .env
```

Consulte o [Guia de Configuração](configuration.md) para a lista completa de variáveis.

---

## Suporte a Navegador para Sessões Autenticadas

Para utilizar o modo `AUTHENTICATED_PUBLIC` (inspeção de perfis públicos em redes com login-wall como Instagram via Chromium isolado):

```bash
playwright install chromium
```
