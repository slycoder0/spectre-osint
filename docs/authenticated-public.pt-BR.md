# Sessões Públicas Autenticadas (Authenticated Public)

[English](authenticated-public.md) | [Português 🇧🇷](authenticated-public.pt-BR.md)

O SPECTRE possui o modo de coleta **Authenticated Public** (`AUTHENTICATED_PUBLIC`), permitindo que o investigador visualize perfis públicos em plataformas que impõem barreiras de login (*login walls*) contra varreduras anônimas.

---

## O Que É vs. O Que Não É

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PRINCÍPIOS DO AUTHENTICATED PUBLIC                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✔  Sessão do próprio operador para carregar páginas públicas de perfis     │
│  ✔  Login manual interativo em janela visível de navegador                  │
│  ✔  Isolamento estrito em perfis Chromium pertencentes ao SPECTRE           │
│  ✖  NÃO é acesso privado (sem mensagens diretas, posts de amigos ou cofres) │
│  ✖  NÃO armazena senhas (o SPECTRE nunca solicita nem grava senhas)         │
│  ✖  NÃO é quebra de CAPTCHA ou evasão stealth de TLS                        │
│  ✖  NUNCA toca no navegador pessoal do operador ou em seus cookies pessoais │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Plataformas Suportadas

As seguintes plataformas são suportadas em `AUTH_PLATFORMS` (`browser/models.py`):
- `instagram`
- `facebook`
- `threads`
- `tiktok`
- `x`
- `twitch`

Quando nenhuma sessão autenticada estiver configurada, o SPECTRE realiza a consulta anônima. Se um login wall for detectado, registra `LOGIN_REQUIRED` e prossegue com as demais fontes da investigação.

---

## Arquitetura de Navegador e Isolamento de Perfis

O SPECTRE suporta dois backends de navegador (`SPECTRE_BROWSER_BACKEND`):
1. **Google Chrome CDP (Loopback):** Inicia uma instância separada do Chrome conectada exclusivamente a `127.0.0.1` em porta dinâmica (`9222–9299`).
2. **Backend Playwright:** Gerencia contextos de navegação via drivers do Playwright.

### Barreiras de Segurança

- **Perfis Dedicados:** Todos os perfis residem em `~/.local/share/spectre/browser-profiles` (ou `SPECTRE_BROWSER_PROFILES_DIR`) e contêm o arquivo de segurança `.spectre-owned`.
- **Rejeição de Navegador Pessoal:** O motor inspeciona caminhos e dispara `PathSafetyError` se apontado para pastas pessoais do Chrome ou Edge (`User Data`).
- **Restrição de Loopback:** As portas de depuração remota escutam estritamente em `127.0.0.1` e rejeitam conexões em `0.0.0.0` ou interfaces de rede externas.

---

## Gerenciamento de Sessões via Linha de Comando (CLI)

### 1. Login Manual Interativo

Para autenticar em uma plataforma:

```bash
spectre auth login instagram
```

Uma janela visível de navegador se abrirá na tela de login oficial da plataforma. O operador realiza a autenticação normalmente (incluindo 2FA/MFA se ativo). Após o login, pressione **Enter** no terminal para salvar o estado da sessão.

### 2. Verificar Sessões Ativas

```bash
spectre auth status
```

Exemplo de saída:
```text
AUTHENTICATED PUBLIC SESSIONS
Platform     Status    Storage    Last Verified
Instagram    ACTIVE    file       2026-08-27 15:30 UTC
Facebook     OFF       -          -
X            ACTIVE    keyring    2026-08-27 14:15 UTC
```

### 3. Logout e Remoção de Sessão

```bash
spectre auth logout instagram
```

---

## Armazenamento e Segurança da Sessão

Os cookies de sessão são salvos localmente em `storage_state.json` no diretório de autenticação da plataforma ou protegidos pelo Keyring do sistema operacional (`keyring_enabled=True`).

- Em sistemas POSIX, diretórios de autenticação são criados com permissão `0700` e arquivos de sessão com `0600`.
- Arquivos de sessão, cookies e tokens são **rigorosamente ignorados pelo Git** e nunca devem ser commitados.
- O comando `spectre doctor` inspeciona apenas o estado booleano da sessão (`ACTIVE` vs `NOT_CONFIGURED`), sem nunca ler ou expor cookies em texto claro.
