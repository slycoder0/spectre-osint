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
1. **Google Chrome CDP (Loopback):** Inicia uma instância dedicada do Chrome vinculando estritamente a `127.0.0.1` em portas dinâmicas (`9222–9299`).
2. **Playwright Backend:** Gerencia contextos de automação via drivers Playwright.

### Fronteiras de Segurança
- **Perfis Dedicados:** Todos os perfis residem sob `~/.local/share/spectre/browser-profiles` (ou `SPECTRE_BROWSER_PROFILES_DIR`) e possuem marcador de segurança `.spectre-owned`.
- **Rejeição de Navegador Pessoal (`PathSafetyError`):** O motor inspeciona caminhos e recusa categoricamente conectar-se a pastas pessoais `User Data` do Chrome ou Edge do operador.
- **Isolamento de Rede:** Portas de depuração remota vinculam-se exclusivamente a `127.0.0.1` e recusam conexões a `0.0.0.0` ou interfaces externas de rede.

---

## 4. Armazenamento de Sessões & Segurança

Os cookies de sessão são armazenados localmente em `storage_state.json` sob o diretório de autenticação da plataforma ou protegidos pelo chaveiro do sistema operacional (`SPECTRE_KEYRING=true`):
- Em sistemas POSIX, diretórios de autenticação são criados com modo `0700` e arquivos de sessão com modo `0600`.
- Arquivos de sessão, cookies e tokens são **estritamente ignorados pelo git** e nunca são commitados no repositório.
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

# Encerrar e remover a sessão local de uma plataforma
spectre auth logout instagram

# Alias para logout — remove os arquivos de sessão local para a plataforma informada
spectre auth clear instagram

# Listar todas as plataformas e status de sessão
spectre auth list
```
