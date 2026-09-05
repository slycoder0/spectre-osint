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

## Proveniência

A proveniência no SPECTRE existe em dois níveis distintos. **Eles não têm o mesmo alcance.**

### Nível de registro (aplica-se de forma ampla)

`Entity`, `Evidence`, `Relationship`, `TimelineEvent` e `PivotSuggestion` (`spectre_osint/core/entities.py`) possuem um campo `source` — uma **string livre**, não um enum fechado. `Finding` não possui campo `source`: sua origem é dada por `module`, `title` e pela lista `evidence` associada (que pode estar vazia em achados derivados de parsing local, como o DNS do domínio de e-mail).

### Nível de campo (convenção de enriquecimento de perfis)

Proveniência **por campo** não é um contrato universal de `Finding.data`. Desde B2-03A ela é um contrato *validado* — `ObservedField`, em `spectre_osint/modules/username/observed.py` — mas com alcance restrito ao enriquecimento de perfis de username (`spectre_osint/modules/username/enrichment.py`), exposto exclusivamente sob a chave `data["observed"]` dos achados do módulo `username`. O modelo valida o que é escrito; o **transporte permanece** um mapeamento JSON comum:

```json
{
  "observed": {
    "display_name": {
      "value": "Alice Developer",
      "original": "Alice Developer (@alice_osint) - GitHub",
      "source": "github_api.name",
      "observed_at": "2026-09-01T12:00:00.000000+00:00",
      "provider_slug": "github",
      "source_method": "JSON_API",
      "source_url": "https://api.github.com/users/alice_osint"
    }
  }
}
```

`provider_slug`, `source_method`, `source_url`, `derived_from`, `rejected_by` e `items` são **aditivos** e omitidos quando desconhecidos. Em campos com valor de lista (`social_links`, `external_links`), `items` guarda a proveniência exata de cada membro, e o nível da linha declara `source: "multiple"` / `source_method: "MIXED"` quando os membros vêm de extratores diferentes, em vez de atribuir todos ao último. Uma linha gravada antes de B2-03A, com apenas as quatro chaves originais, continua válida e legível. Não houve migração de banco. Veja [Regras de Enriquecimento](technical/enrichment.md#3-estrutura-de-proveniencia-de-campo-observado-b2-03a) para a semântica de cada chave.

Limites que o consumidor precisa respeitar:

- **Não presuma essa estrutura em qualquer campo de `Finding.data`.** No mesmo achado de username, chaves de nível superior como `display_name`, `bio` ou `website` são valores simples e sem etiqueta de proveniência — achatados a partir de `observed` (`flatten_observed`) ou, em consultas não autenticadas fora de `json_api`, preenchidos por fallback do parsing da página.
- **Outros analisadores gravam valores diretos.** O módulo `email`, por exemplo, coloca `mx`, `txt`, `spf`, `dmarc` e `mail_providers` diretamente em `Finding.data`, sem invólucro de `value`/`source`.
- **Campos ausentes de `observed` não recebem proveniência sintética.** A correlação de identidades trata proveniência como melhor-esforço e cai para `source: ""` quando o campo não foi observado com etiqueta.
- O valor de `source` é uma string concreta do ponto de extração (ex.: `github_api.name`, `html_og.title`, `html_jsonld.sameAs`), não um identificador genérico. Consulte [Modelo de Evidências](concepts/evidence.md) para a semântica desses identificadores.
- **Se o achado contém a chave `observed`, o modelo validado é a autoridade.** Desde B2-03B1 os consumidores de evidência — correlação de identidades, apresentação e extração de indicadores de pivô — validam `data["observed"]` e derivam dele os atributos observados de perfil. As chaves de nível superior seguem sendo escritas para compatibilidade, mas **deixam de ser evidência** para qualquer atributo que o canal observado cubra: um `display_name` de nível superior em conflito com `observed["display_name"]` perde.
- **A decisão é por presença da chave, não por conteúdo.** `observed` **ausente** significa que nenhum transporte observado foi escrito — só nesse caso o fallback de nível superior continua ativo, o que preserva achados persistidos antes do contrato. `observed` **presente** significa que o canal autoritativo existe, incluindo quando vale `{}` (enriquecimento vazio e autoritativo), `None`, `[]` ou um mapeamento malformado.
- **Transporte presente e inválido falha fechado.** Nenhum atributo observado é exposto e **não há fallback** para as chaves de nível superior. O achado do perfil continua existindo — `platform`, `username`, `profile_url`/`final_url`, `check_status` e `entity_id` são o registro de que um perfil público foi verificado, não uma alegação de enriquecimento, e `PERFIL EXISTE != MESMA PESSOA`. O `Finding.data` original permanece intacto: a autoridade é decidida na **leitura**, sem migração de banco e sem validação no momento da gravação.
- **`rejected_by` presente significa evidência inativa a jusante.** O campo não entra em correlação (nem como sinal positivo, nem como conflito), não aparece como linha observada ativa na apresentação e não se torna indicador de pivô. A observação rejeitada **permanece** no transporte original e na proveniência validada, porque foi observada e depois rejeitada. `UM VALOR REJEITADO SEGUE REJEITADO`.
- **A forma semântica também é verificada pelo consumidor.** Um campo escalar com valor de lista (ou o inverso) é suprimido em vez de convertido — `["Alice"]` nunca vira a string `"['Alice']"`. Apenas aquele campo é suprimido; o restante do mapeamento válido continua ativo.
- **`ObservedField` modela a distinção `atributo observado != atributo civil verificado`.** O modelo não *garante* por si que todo consumidor a imponha; B2-03A introduziu o contrato e B2-03B1 passou a impô-lo nos consumidores de evidência acima. Para links de perfil cruzado, B2-03B1 usa os **valores** validados da lista; explicar **qual `ObservedItem`** sustentou o link é B2-03B3, e a explicação segue grosseira até lá. Preservação de originais brutos por item e emissão de `rejected_by` pelo produtor **não** estão implementadas.
