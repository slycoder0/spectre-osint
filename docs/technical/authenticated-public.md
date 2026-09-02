# Modo Authenticated Public

O modo **Authenticated Public** (`AUTHENTICATED_PUBLIC`) permite inspecionar perfis públicos em plataformas que impõem barreiras de autenticação (login-wall).

---

## 1. Princípios Fundamentais

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       AUTHENTICATED PUBLIC PRINCIPLES                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✔  Sessão do próprio operador usada para ler páginas públicas da web       │
│  ✔  Login manual interativo em janela visível do navegador                  │
│  ✔  Isolamento estrito em perfil dedicado do Chromium (.spectre-owned)      │
│  ✖  NÃO é acesso a dados privados (mensagens, DMs ou feeds fechados)        │
│  ✖  NÃO armazena senhas (o SPECTRE nunca recebe ou salva credenciais)       │
│  ✖  NÃO enfraquece o modelo de evidências (autenticado ≠ confirmado)        │
│  ✖  NUNCA toca nos perfis pessoais ou cookies do seu navegador principal    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Semântica Probatória de Plataformas com Login-Wall

A autenticação permite ultrapassar a barreira de acesso anônimo para **observar metadados públicos**. Ela **não** transforma magicamente um perfil em `CONFIRMED`.

Por exemplo, no caso do Instagram (`confidence_strategy: never_confirmed` em `sites.yaml`), o classificador de evidência autenticada retorna:
- **Status:** `UsernameCheckStatus.LIKELY`
- **Confiança:** `Confidence.HIGH`

Isso preserva a disciplina probatória: temos alta certeza dos metadados observados, mas a plataforma não fornece um contrato formal de API para confirmação de identidade civil.

Quando nenhuma sessão autenticada está configurada para uma plataforma, o SPECTRE consulta a plataforma anonimamente. Se encontrar uma barreira de login, registra o status `LOGIN_REQUIRED` e continua normalmente a investigação das demais plataformas.

---

## 3. Arquitetura do Navegador & Isolamento de Perfis

O SPECTRE suporta dois backends de navegador (`SPECTRE_BROWSER_BACKEND`):
1. **Google Chrome CDP (Loopback):** Inicia uma instância dedicada do Chrome em perfil próprio, com depuração remota vinculada a `127.0.0.1`.
2. **Playwright Backend:** No login manual, abre um contexto persistente do Chromium (`launch_persistent_context`) sobre um perfil dedicado do SPECTRE. Na coleta autenticada, sobe um Chromium headless e reinjeta o estado salvo em um contexto novo.

### Porta de Depuração do Chrome CDP

O fluxo de lançamento atual (`browser/manager.py::_acquire_cdp_endpoint`) **não** reserva uma porta fixa:

- O comando é montado por `build_chrome_command(...)` com `--remote-debugging-address=127.0.0.1` e `--remote-debugging-port=0`.
- A porta `0` delega a escolha ao Chrome/sistema operacional, que abre uma porta livre arbitrária de loopback.
- O SPECTRE descobre o endpoint real lendo o arquivo `DevToolsActivePort` **dentro do perfil dedicado** (`wait_for_spectre_cdp_ready`), ignorando um arquivo remanescente de execução anterior e só aceitando o endpoint quando `http://127.0.0.1:<porta>/json/version` responde e o `webSocketDebuggerUrl` corresponde.
- A leitura do `DevToolsActivePort` é recusada com `PathSafetyError` quando o caminho aparenta ser um perfil pessoal de Chrome/Edge; diretórios sem o marcador `.spectre-owned` simplesmente não produzem endpoint algum.

Consequência operacional: **não presuma uma faixa fixa de portas** (por exemplo `9222–9299`) para o fluxo de lançamento atual. As constantes `CDP_PORT_MIN`/`CDP_PORT_MAX` e os auxiliares `preferred_cdp_port()` / `bind_loopback_port()` ainda existem em `browser/chrome.py`, mas hoje são exercitados apenas pela suíte de testes — o caminho de lançamento em produção não os chama.

!!! note "Verificação de porta no `spectre doctor`"
    A linha *Chrome CDP* do `spectre doctor` faz apenas uma tentativa de conexão TCP a `127.0.0.1:9222`. Como o lançador usa porta atribuída pelo SO, essa linha normalmente reporta `inactive` mesmo com uma sessão SPECTRE do Chrome ativa em outra porta. O `doctor` não inicia o Chrome nem consulta o `DevToolsActivePort`.

### Fronteiras de Segurança
- **Perfis Dedicados (Playwright):** Perfis do Chromium residem sob `SPECTRE_BROWSER_PROFILES_DIR` — por padrão `~/.local/share/spectre/browser-profiles` no Linux/BSD e `~/Library/Application Support/spectre/browser-profiles` no macOS — e possuem marcador de segurança `.spectre-owned`.
- **Perfis Dedicados (Chrome CDP):** Perfis do Chrome residem em árvore própria e separada, sob `SPECTRE_CHROME_PROFILES_DIR` — por padrão `%USERPROFILE%\.spectre\chrome` no Windows/WSL, `~/Library/Application Support/spectre/chrome` no macOS e `~/.local/share/spectre/chrome-profiles` no Linux —, também com marcador `.spectre-owned`.
- **Rejeição de Navegador Pessoal (`PathSafetyError`):** O motor inspeciona caminhos e recusa categoricamente conectar-se a pastas pessoais `User Data` do Chrome ou Edge do operador.
- **Isolamento de Rede:** A depuração remota é vinculada exclusivamente a `127.0.0.1` e recusa conexões a `0.0.0.0` ou interfaces externas de rede.

---

## 4. Estado de Autenticação em Repouso

O SPECTRE **nunca recebe nem grava senhas**. O que existe em repouso é estado de sessão de navegador, e **o formato depende do backend usado no login**. Não presuma que todo o material sensível está em `storage_state.json` ou no chaveiro.

### 4.1 Backend Playwright

- Ao detectar login concluído, o SPECTRE captura `context.storage_state()`. Esse blob segue o esquema `{ "cookies": [...], "origins": [...] }` e pode conter **cookies e também estado por origem (`localStorage`)**, não apenas cookies. Se a captura falhar, há um fallback que monta o blob apenas com os cookies do contexto.
- O blob é persistido pelo `SessionStore` (`browser/sessions.py`), que **prefere o chaveiro do sistema operacional** quando disponível (`SPECTRE_KEYRING=true`); nesse caso o arquivo local é removido e `profile.json` registra `storage="keyring"`.
- Quando o chaveiro está desabilitado, indisponível ou a gravação nele falha, o mesmo blob é gravado em `storage_state.json` sob o diretório de autenticação da plataforma, como **arquivo local com permissão restrita**, e `profile.json` registra `storage="file"`.
- O login roda em um contexto persistente (`launch_persistent_context`) sobre o perfil dedicado do Chromium. Portanto o **próprio diretório de perfil também retém estado de navegador em disco**, independentemente do blob extraído.
- A coleta autenticada (`fetch_public`) reinjeta apenas o blob do `SessionStore` em um contexto novo.

### 4.2 Backend Google Chrome CDP

- O estado autenticado real permanece no **perfil persistente dedicado do Chrome pertencente ao SPECTRE** — cookies, armazenamento por origem e demais artefatos de estado do Chrome ficam nessa árvore de perfil, gravados pelo próprio Chrome.
- O registro gravado no `SessionStore` é um **sentinela compatível com o esquema, sem segredos** (`cdp_session_sentinel`): `backend: "CHROME_CDP_SESSION"`, `cookies: []`, `origins: []` e um marcador `spectre`. Esse sentinela **não é equivalente ao estado de sessão do navegador** e não permite restaurar a sessão por si só.
- A coleta autenticada por CDP descarta explicitamente o `storage_state` recebido: cookies do Chrome nunca são transplantados para um contexto Playwright. A sessão é usada reconectando-se ao perfil dedicado.

### 4.3 Consequências para Proteção, Backup e Remoção

Proteger, copiar ou apagar artefatos de autenticação exige tratar **todos** os locais abaixo, conforme o backend:

| Artefato | Onde vive | Contém segredo? |
| :--- | :--- | :--- |
| Registro de sessão Playwright | Chaveiro do SO **ou** `<auth_dir>/<plataforma>/storage_state.json` | Sim (cookies e possivelmente `localStorage`) |
| Perfil dedicado do Chromium (Playwright) | `SPECTRE_BROWSER_PROFILES_DIR` ou o padrão da plataforma | Sim (estado de navegador em disco) |
| Perfil dedicado do Chrome (CDP) | `SPECTRE_CHROME_PROFILES_DIR` ou o padrão da plataforma | Sim (estado de navegador em disco) |
| Sentinela CDP no `SessionStore` | Chaveiro do SO **ou** `storage_state.json` | Não (sem cookies, sem tokens) |
| Metadados de sessão | `<auth_dir>/<plataforma>/profile.json` | Não (status, nome do perfil, modo de armazenamento, notas) |

- `spectre auth logout <plataforma>` (e seu alias `clear`) apaga o registro do `SessionStore` (entrada de chaveiro, `storage_state.json` e `profile.json`) e remove **os dois** perfis dedicados — o do Chromium/Playwright e o do Chrome CDP. Cada etapa é tolerante a falhas e registra aviso sem abortar as demais, então uma remoção parcial é possível se o sistema de arquivos recusar a operação. Contas remotas e o navegador pessoal não são afetados.
- Em sistemas POSIX, diretórios de autenticação e de perfil são criados com modo `0700` e arquivos de sessão com modo `0600`. O SPECTRE **não aplica criptografia própria**: a proteção é a do chaveiro do SO ou a permissão do arquivo local.
- Arquivos de sessão, cookies e tokens são **ignorados pelo git** e nunca são commitados no repositório.
- O comando `spectre doctor` lê apenas os metadados de sessão em `profile.json` (podendo reportar qualquer status válido de `SessionStatus` ou `UNKNOWN`), nunca abre o arquivo `storage_state.json` e **nunca lê ou imprime valores de cookies em texto claro**.

---

## 5. Plataformas Suportadas

Definidas em `AUTH_PLATFORMS` (`browser/models.py`):
- `instagram`
- `facebook`
- `threads`
- `tiktok`
- `x`
- `twitch`

---

## 6. Gestão de Sessões via CLI

```bash
# Iniciar login interativo (abre o Chromium visível para o login manual)
spectre auth login instagram

# Inspecionar status de sessões ativas
spectre auth status

# Verificar validade de uma sessão salva
spectre auth verify instagram

# Encerrar e remover a sessão local e o perfil dedicado do SPECTRE para a plataforma (não afeta contas remotas nem o navegador pessoal)
spectre auth logout instagram

# Alias para logout — remove a sessão salva e limpa o perfil dedicado do SPECTRE para a plataforma informada
spectre auth clear instagram

# Listar todas as plataformas e status de sessão
spectre auth list
```
