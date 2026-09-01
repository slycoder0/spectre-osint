# Resultados & Dicionário de Status

O SPECTRE adota uma taxonomia determinística para classificar os resultados obtidos em cada plataforma e indicador investigado.

---

## Principais Estados de Verificação (`UsernameCheckStatus`)

Esta tabela resume os status mais frequentes observados em investigações de username:

| Status | Representação Visual | Significado Técnico e Investigativo |
| :--- | :--- | :--- |
| **`CONFIRMED`** | <span class="status-pill status-confirmed">CONFIRMED</span> | O perfil existe na plataforma alvo. O contrato da API JSON foi validado e o campo estrutural de identidade (`json_id_field`) retornou um valor escalar válido e não-vazio. |
| **`LIKELY`** | <span class="status-pill status-likely">LIKELY</span> | Evidências fortes de presença pública foram encontradas (ex: metadados extraídos via sessão autenticada no Instagram ou convergência de sinais HTML positivos), sem âncora unívoca de API JSON. |
| **`INCONCLUSIVE`** | <span class="status-pill status-inconclusive">INCONCLUSIVE</span> | Resposta ambígua, página genérica de erro ou desafio anti-bot intermediário. O SPECTRE não faz suposições sobre a existência da conta. |
| **`NOT_FOUND`** | <span class="status-pill status-not-found">NOT_FOUND</span> | O contrato do provedor não observou um perfil válido para o alvo (código 404 retornado, redirecionamento para homepage/busca ou resposta JSON 200 sem campo de identidade configurado). |
| **`LOGIN_REQUIRED`** | <span class="status-pill status-login-required">LOGIN_REQUIRED</span> | A plataforma exige uma sessão conectada para exibir o perfil público (código 401/403 em plataformas de login-wall; consulte o modo `spectre auth`). |
| **`BLOCKED`** | <span class="status-pill status-blocked">BLOCKED</span> | A requisição foi bloqueada por barreiras de borda (Cloudflare/WAF) ou a plataforma retornou status 401/403 em consultas públicas anônimas. O SPECTRE não realiza evasão ativa. |
| **`RATE_LIMITED`** | <span class="status-pill status-rate-limited">RATE_LIMITED</span> | A plataforma retornou HTTP 429 ou esgotamento de quota. O SPECTRE aplica backoff automático. |
| **`PROVIDER_UNAVAILABLE`** | <span class="status-pill status-unavailable">UNAVAILABLE</span> | Timeout de rede, erro 5xx recorrente, falha determinística de TLS ou resposta incompatível com o contrato esperado. |

👉 Para a taxonomia técnica completa (incluindo `SESSION_EXPIRED`, `CHALLENGE_REQUIRED`, etc.), consulte [Semântica de Status](concepts/statuses.md).

---

## Níveis de Confiança (`Confidence`)

O enum `Confidence` (`spectre_osint/core/types.py`) expressa o grau de certeza técnica da evidência:

- **`CONFIRMED`:** Valor ou resultado cuja validade técnica foi estabelecida por observação direta, validação ou derivação determinística, sem depender de heurística. A proveniência é registrada separadamente e pode vir de API, DNS, parsing local ou input validado; `CONFIRMED` não implica confirmação de identidade civil nem transforma input do operador em evidência externa.
- **`HIGH`:** Evidência de alta confiabilidade com marcadores claros e consistentes (ex: metadados observados em sessão autenticada com contrato estrito).
- **`MEDIUM`:** Evidência provável que depende de contexto semântico ou heurística de marcação HTML.
- **`LOW`:** Pista inicial, menção em texto livre ou similaridade de strings.

*Nota: O status `LIKELY` não possui um nível de confiança fixo e pode receber `MEDIUM` ou `HIGH` conforme o contrato do provedor.*

---

## Proveniência de Campo (`ObservedField`)

Todos os dados extraídos recebem uma etiqueta imutável de proveniência (`source`):

```json
{
  "display_name": {
    "value": "Alice Developer",
    "source": "github_api.name",
    "observed_at": "2026-09-01T12:00:00Z"
  }
}
```
