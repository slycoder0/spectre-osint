# Semântica de Status, Achados & Confiança

O SPECTRE diferencia rigorosamente entre o status de verificação de username no catálogo (`UsernameCheckStatus`), o status geral do achado (`FindingStatus`), o status da sessão autenticada (`SessionStatus`) e o nível de confiança (`Confidence`).

---

## 1. Status de Verificação de Username (`UsernameCheckStatus`)

O enum `UsernameCheckStatus` (`spectre_osint/core/types.py`) possui exatamente 13 estados:

| Status | Significado Técnico |
| :--- | :--- |
| **`CONFIRMED`** | O perfil existe na plataforma alvo. O contrato da API JSON foi validado e o campo estrutural de identidade (`json_id_field`) retornou um valor escalar válido e não-vazio. |
| **`LIKELY`** | Evidências fortes de presença pública foram encontradas (ex: metadados extraídos via sessão autenticada no Instagram ou convergência de sinais HTML), sem âncora unívoca de API JSON. |
| **`NOT_FOUND`** | O contrato do provedor não observou um perfil válido para o alvo (código 404 retornado, redirecionamento para homepage/busca ou payload JSON sem campo de identidade configurado). |
| **`INCONCLUSIVE`** | Resposta ambígua, corpo truncado ou desafio intermediário. O SPECTRE não presume existência nem ausência. |
| **`BLOCKED`** | Requisição bloqueada por barreira de borda (Cloudflare/WAF) ou código 401/403 de acesso não autorizado em plataformas públicas anônimas. |
| **`LOGIN_REQUIRED`** | A plataforma exige autenticação para exibir perfis públicos (código 401/403 em plataformas de login-wall ou redirecionamento para tela de login). |
| **`RATE_LIMITED`** | Código HTTP 429 ou esgotamento de quota de requisições. Aciona a política de backoff. |
| **`PROVIDER_UNAVAILABLE`** | Timeout de conexão, erro 5xx recorrente, falha determinística de TLS ou resposta incompatível com o contrato esperado. |
| **`SESSION_EXPIRED`** | A sessão autenticada previamente configurada expirou ou foi invalidada pela plataforma remota. |
| **`CHALLENGE_REQUIRED`** | A plataforma remota solicitou verificação adicional de segurança (ex: checkpoint de conta). |
| **`CAPTCHA_REQUIRED`** | A plataforma exigiu resolução de CAPTCHA. O SPECTRE não resolve CAPTCHAs automaticamente. |
| **`TEMPORARILY_LIMITED`** | Ação temporariamente restrita pela plataforma remota para a sessão atual. |
| **`OAUTH_BROWSER_REJECTED`**| O navegador ou fluxo OAuth foi rejeitado pelas políticas de segurança da plataforma. |

---

## 2. Status Geral do Achado (`FindingStatus`)

O enum `FindingStatus` possui exatamente 18 valores, aplicados a todas as classes de investigação (DNS, domínios, IPs, buscas e menções):

1. `FOUND`
2. `NOT_FOUND`
3. `NOT_CONFIGURED`
4. `PROVIDER_UNAVAILABLE`
5. `INFERENCE`
6. `ERROR`
7. `SKIPPED`
8. `AUTHORIZATION_REQUIRED`
9. `INCONCLUSIVE`
10. `LOGIN_REQUIRED`
11. `BLOCKED`
12. `RATE_LIMITED`
13. `SESSION_EXPIRED`
14. `CHALLENGE_REQUIRED`
15. `CAPTCHA_REQUIRED`
16. `TEMPORARILY_LIMITED`
17. `OAUTH_BROWSER_REJECTED`
18. `OBSERVED` (Menções públicas indexadas ou referências contextuais encontradas em motores de busca; nunca substitui `CONFIRMED` ou `LIKELY` do catálogo).

---

## 3. Níveis de Confiança (`Confidence`)

O enum `Confidence` possui exatamente 4 valores:

- **`CONFIRMED`:** Valor ou resultado cuja validade técnica foi estabelecida por observação direta, validação ou derivação determinística, sem depender de heurística. A proveniência é registrada separadamente e pode vir de API, DNS, parsing local ou input validado; `CONFIRMED` não implica confirmação de identidade civil nem transforma input do operador em evidência externa.
- **`HIGH`:** Alta confiabilidade com marcadores claros e consistentes (ex: extração autenticada com contrato estrito no Instagram).
- **`MEDIUM`:** Evidência provável baseada em heurísticas ou contexto semântico convergente.
- **`LOW`:** Pista inicial ou menção em texto livre.

---

## 4. Status de Sessões Autenticadas (`SessionStatus`)

O enum `SessionStatus` possui exatamente 14 estados que refletem o ciclo de vida da autenticação:

1. `NOT_CONFIGURED` — Nenhuma sessão configurada para a plataforma.
2. `ACTIVE` — Sessão autenticada válida e pronta para consultas.
3. `EXPIRED` — Sessão com cookies expirados ou revogados.
4. `CHALLENGE_REQUIRED` — Checkpoint de segurança exigido pela plataforma.
5. `CAPTCHA_REQUIRED` — CAPTCHA solicitado na tela de login.
6. `BLOCKED` — Bloqueio de acesso detectado.
7. `TEMPORARILY_LIMITED` — Limitação temporária imposta pela rede social.
8. `OAUTH_BROWSER_REJECTED` — Navegador automatizado recusado pelo fluxo OAuth.
9. `CHROME_NOT_FOUND` — Executável do Google Chrome não encontrado no sistema.
10. `CDP_UNAVAILABLE` — Endpoint CDP inacessível em loopback.
11. `CHROME_PROFILE_LOCKED` — Perfil do Chrome em uso ou travado.
12. `WINDOWS_CDP_LAUNCH_FAILED` — Falha ao iniciar Chrome CDP em ambiente Windows/WSL.
13. `LOGIN_REQUIRED` — Login manual necessário.
14. `UNAVAILABLE` — Login por navegador indisponível para esta plataforma.
