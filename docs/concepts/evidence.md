# Modelo de Evidências & Invariantes Probatórios

O **SPECTRE OSINT** foi concebido sob princípios rigorosos de disciplina probatória: **dados públicos observados são registrados com exatidão técnica, a origem de cada registro é preservada, e identidades nunca são presumidas a partir de respostas parciais.**

---

## Os Quatro Invariantes Fundamentais

O motor do SPECTRE é governado por quatro invariantes arquiteturais:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                      INVARIANTES PROBATÓRIOS FUNDAMENTAIS                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. HTTP 200 ≠ IDENTIDADE CONFIRMADA (Exige contrato estrutural do catálogo)│
│  2. MESMO USERNAME ≠ MESMA PESSOA (Reuso de handle não prova pessoa física) │
│  3. INPUT DO OPERADOR ≠ EVIDÊNCIA OBSERVADA (Hipóteses ficam separadas)     │
│  4. CANDIDATO DE BUSCA ≠ PERFIL CONFIRMADO (Descobertas são pistas)        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. HTTP 200 ≠ Identidade Confirmada

Em investigações automatizadas, respostas HTTP com status `200 OK` frequentemente geram falsos positivos quando interpretadas sem critério:
- Páginas de "Usuário não encontrado" servidas com status 200 (Soft-404).
- Telas de bloqueio de WAF ou desafios de verificação com status 200.
- Payloads JSON válidos onde o objeto de usuário é nulo ou vazio (`{"user": null}`).

### Regra de Verificação do SPECTRE

- **Provedores JSON (`check_method: json_api`):** A confirmação (`CONFIRMED`) exige que o campo estrutural configurado (`json_id_field`) resolva para um valor escalar de identidade não-vazio e significativo (rejeitando strings vazias, apenas espaços, booleanos e listas vazias).
- **Provedores HTML (`check_method: generic_html`):** Evidências HTML positivas produzem no máximo status **`LIKELY`** quando múltiplos sinais independentes convergem (título da página, canonical URL, tags OpenGraph e marcadores de perfil); HTTP 200 ou marcações HTML isoladas nunca produzem `CONFIRMED`.

---

## 2. Mesmo Username ≠ Mesma Pessoa

O fato de um mesmo username (ex: `alice_sec`) existir no GitHub, Reddit e Instagram **não significa** que todos esses perfis pertençam à mesma pessoa física.

O SPECTRE classifica a existência de cada conta como **presença de perfil (`SOCIAL_PROFILE`)**, e **não** como identificação de identidade civil.

A correlação entre perfis é realizada por um motor determinístico separado (`modules/username/identity.py`), que analisa convergência de múltiplos sinais independentes (mesma URL de avatar normalizada, links recíprocos de biografia, domínios pessoais compartilhados).

---

## 3. Entrada do Operador ≠ Evidência Observada

Pistas fornecidas pelo investigador permanecem separadas dos dados observados diretamente na web. O campo `source` é uma **string livre** (não um enum fechado) e o runtime emite hoje três famílias distintas de identificadores:

| Origem | `source` emitido | Onde é atribuído |
| :--- | :--- | :--- |
| **Alvo primário da investigação** | `"user"` | `core/pipeline.py` — a entidade do alvo informado na linha de comando. |
| **Pistas suplementares do operador** | `"operator"` | `core/pipeline.py` — aliases extras (`--alias`), nome (`--name`), e-mail (`--email`) e site/domínio (`--website`), junto das relações `OPERATOR_PROVIDED_ALIAS` / `OPERATOR_PROVIDED_INPUT`. |
| **Campos observados/enriquecidos** | Identificador concreto do ponto de extração, ex.: `github_api.name`, `github.username`, `html_og.title`, `html_jsonld.sameAs`, `html_canonical`, `html_rel_me`, `instagram_og.title` | `modules/username/enrichment.py` — dentro de `data["observed"]` dos achados de username. |

Observações importantes:

- Não existem valores genéricos como `source="observed"` ou `source="platform_api"` no runtime atual.
- As pistas suplementares recebem `Confidence.LOW` nas relações com o alvo e `metadata={"not_identity_evidence": True}`; a entidade em si pode ser criada como `CONFIRMED` apenas no sentido de valor tecnicamente válido (e-mail/domínio bem formado), **nunca** como identificação civil.
- Os identificadores de campo observado são derivados do provedor e do caminho de extração, então **não são idênticos entre plataformas** e novos provedores podem introduzir novos rótulos. Trate-os como strings descritivas, não como um conjunto fechado.
- Proveniência **por campo** existe hoje apenas nessa convenção de enriquecimento de perfis. Consulte [Resultados & Status](../results.md#proveniencia) para o alcance exato.

---

## 4. Candidatos de Busca ≠ Perfis Confirmados

Resultados obtidos através de motores de busca públicos são catalogados como **candidatos de descoberta (`discovered_profile`)**. Eles nunca recebem o status `CONFIRMED` ou `LIKELY` do catálogo a menos que passem pela validação direta do módulo de verificação da plataforma correspondente.
