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

Saída padrão (compacta, no idioma do sistema — aqui em português):

```text
SPECTRE DOCTOR 0.1.0b1
Núcleo: OK (Python 3.13.x, banco SQLite)
Segurança: OK (política SSRF ativa, segredos ocultados)
Configurado: Chrome/Chromium
20 itens opcionais não configurados (navegador, busca, sessões, chaves de API) — `spectre doctor --all` lista todos
Resultado geral: PRONTO, COM RECURSOS OPCIONAIS AUSENTES
```

Itens que exigem ação ou atenção aparecem sempre, cada um com a dica de correção. Para ver
todas as verificações (agrupadas em núcleo, navegador, busca, sessões públicas autenticadas,
provedores de API e segurança), use `spectre doctor --all`. Para outro idioma, `spectre --lang en doctor`.

O status final é `READY`, `READY WITH OPTIONAL FEATURES MISSING` ou `ACTION REQUIRED` (traduzido no terminal; em inglês no `--json`). O comando retorna código de saída `1` apenas em `ACTION REQUIRED`.

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

- **Relatórios HTML:** Pasta local `reports/`. O nome de cada artefato é **gerado pelo runtime** a partir dos identificadores do caso e do alvo (`core/paths.py::artifact_stem`): cada identificador é convertido em slug, pode ser truncado quando excede o limite de tamanho — recebendo então um sufixo de hash determinístico — e o nome final termina com um hash do par caso+alvo. Não presuma um nome previsível ou legível: localize o arquivo pela listagem de `reports/` ou pelos caminhos que `spectre report` imprime.
- **Banco de Dados SQLite:** Armazenado em `data/spectre.db`.
- **Exportação:** Gere relatórios a qualquer momento com `spectre report`.
