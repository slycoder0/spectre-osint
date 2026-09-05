# Regras de Enriquecimento de Metadados

O módulo de enriquecimento (`spectre_osint/modules/username/enrichment.py`) extrai, normaliza e padroniza metadados observados em páginas e APIs públicas.

---

## 1. Limpeza de Nomes de Exibição (`clean_display_name`)

A função `clean_display_name` executa as seguintes etapas:
1. **Normalização de Espaços:** Reduz múltiplos espaços em branco a um único espaço.
2. **Remoção de Padrões de Handle:** Remove menções explícitas ao handle investigado (ex: `(@alice_osint)`).
3. **Remoção de Sufixos de Título de Plataforma (`_TITLE_SUFFIXES`):** Remove sufixos institucionais conhecidos como ` · GitHub`, ` | Dev Community`, ` on Instagram`, ` - Chess.com`, ` - Docker Hub`, ` - WordPress User Profile`, etc.
4. **Remoção de Prefixos/Sufixos de Plataforma Conhecidos:** Segmenta delimitadores (`|`, `·`, `•`, `—`, `–`, `:`) e remove nomes conhecidos do catálogo.
5. **Rejeição de Equivalência ao Handle:** Se o resultado for idêntico ao username ou nome normalizado do alvo, o campo é descartado como redundante.
6. **Filtro de Nomes Genéricos (`is_generic_display_name`):** Rejeita textos institucionais genéricos como *"Where the world builds software"* ou *"Cyber Security Training"*.

---

## 2. Filtragem de Websites Pessoais (`_personal_website`)

A função `_personal_website` valida se a URL extraída é um domínio pessoal genuíno ou apenas um link interno para a própria plataforma:
- URLs cujo host esteja na lista de plataformas conhecidas (`_PLATFORM_HOSTS`, como `github.com`, `reddit.com`, `instagram.com`) são rejeitadas como sites pessoais.

---

## 3. Estrutura de Proveniência de Campo Observado (B2-03A)

Desde B2-03A existe um modelo validado — `ObservedField`, em `spectre_osint/modules/username/observed.py`. `enrich_profile` constrói e valida cada observação como `ObservedField` internamente e então **serializa** para o mesmo mapeamento JSON simples que `data["observed"]` sempre carregou. O transporte não mudou: `Finding.data["observed"]` continua sendo um dicionário comum.

```python
{
    "value": "Alice Developer",
    "original": "Alice Developer (@alice_osint) - GitHub",
    "source": "github_api.name",
    "observed_at": "2026-09-01T12:00:00.000000+00:00",
    # aditivos, omitidos quando desconhecidos:
    "provider_slug": "github",
    "source_method": "JSON_API",
    "source_url": "https://api.github.com/users/alice_osint"
}
```

### Núcleo compatível com o formato anterior

- `value` pode ser uma string ou, para `external_links` / `social_links`, uma lista de strings. Uma observação é **escalar ou de lista**, e `value` e `original` usam **a mesma forma**: um `value` escalar com `original` em lista (ou o inverso) não é nenhuma das duas e é recusado na validação, porque o consumidor não teria como associar cada valor normalizado ao seu texto de origem. Quando as duas são listas, precisam ainda ter **a mesma cardinalidade**: `value=["a", "b"]` com `original=["raw-a"]` concorda na forma e continua ilegível — sobra um valor sem texto de origem. `project_items()` já constrói as duas listas em par; a regra fecha a porta serializada. Linhas legadas seguem válidas em qualquer uma das duas formas, desde que suas próprias listas casem — a regra é apenas que forma e cardinalidade concordem, `original` não precisa ser igual a `value`, a ordem não é alterada e nenhuma normalização nova é introduzida.
- `source` é derivado do provedor e do caminho de extração — por exemplo `github_api.<campo>` para respostas JSON, `github.username` para o handle normalizado, e `html_og.title`, `html_title`, `html_canonical`, `html_jsonld.<campo>` ou `html_rel_me` para extração de HTML. **Essas strings estão congeladas em B2-03A** e permanecem byte a byte idênticas para observações escalares e para listas de origem única. A única exceção é declarada abaixo: uma lista com itens de origens diferentes passa a informar `"multiple"` no nível da linha, porque nomear um único extrator ali seria falso.
- `observed_at` é serializado com `datetime.isoformat()` (deslocamento `+00:00`), exatamente como antes. Observações novas exigem timestamp com fuso horário.
- Campos vazios são omitidos, e o primeiro valor não-vazio para um campo escalar prevalece (`put` não sobrescreve um campo já preenchido).

### Chaves aditivas de proveniência

| Chave | Significado |
| :--- | :--- |
| `provider_slug` | O `slug` declarado pelo catálogo (contrato explícito de B2-02B). Nunca re-derivado do nome de exibição: renomear um provedor não move seu identificador estável. Ausente quando a chamada não recebe definição de site. |
| `source_method` | Origem da observação: `INPUT` (handle informado pelo operador), `JSON_API`, `HTML`, `AUTHENTICATED_PUBLIC` (mesmos extratores de HTML, porém sobre uma busca com sessão conectada — dado público, nunca acesso privado) ou `DERIVED`. |
| `source_url` | URL de onde o payload foi efetivamente lido (`effective_url` do motor), com fallback para `profile_url`. **Proibida em `INPUT`**, que não veio de página alguma: não é apenas o escritor que a omite — o invariante é validado no modelo, na linha (`ObservedField`) e em cada item (`ObservedItem`). |
| `derived_from` | Campo de origem de um valor derivado. Hoje apenas `personal_domain`, com `derived_from="website"`. O cálculo de `personal_domain` não mudou. **`derived_from` e `DERIVED` são duas metades da mesma afirmação**, validadas nos dois sentidos: uma observação derivada precisa nomear sua origem, e só uma observação derivada pode nomear uma. Vale na linha e no item. O token não é interpretado — nenhum vocabulário de origem futura está fixado no código — mas precisa **dizer algo**: uma origem presente vazia ou só com espaços em branco não nomeia campo nenhum e é **recusada**, nunca aparada; um token válido nunca é reescrito. **Todo item `DERIVED` precisa nomear sua própria origem não vazia**, e uma linha `DERIVED` escalar ou **sem** `items` também — não há para onde diferir. A única exceção é a linha agregada descrita abaixo. |
| `rejected_by` | Metadado **de campo** (`ObservedField`), reservado para B2-03B. **B2-03A não emite observações rejeitadas**; um valor rejeitado continua simplesmente omitido. `ObservedItem` **não** carrega estado de rejeição: um item serializado que traga `rejected_by` é inválido (`extra="forbid"`). Semântica de rejeição por item **não** é introduzida em B2-03A. |
| `items` | Proveniência exata **por item** de um campo com valor de lista. Ausente em campos escalares e em linhas de lista gravadas antes deste contrato. |

### Proveniência por item em campos de lista

`social_links` e `external_links` são alimentados por vários extratores na mesma checagem — `<provider>_api.twitter_username`, `html_jsonld.sameAs`, `html_rel_me`. Um único `source` no nível da linha não descreve todos eles, e atribuir o valor vindo da API JSON ao HTML seria uma falsa atribuição. Cada item carrega então a própria proveniência (`ObservedItem`):

```json
"social_links": {
  "value": ["https://x.com/alice", "https://github.com/alice"],
  "original": ["https://x.com/alice", "https://github.com/alice"],
  "source": "multiple",
  "observed_at": "2026-09-01T12:00:00.000000+00:00",
  "provider_slug": "github",
  "source_method": "MIXED",
  "source_url": "https://api.github.com/users/alice",
  "items": [
    {
      "value": "https://x.com/alice",
      "original": "https://x.com/alice",
      "source": "github_api.twitter_username",
      "observed_at": "2026-09-01T12:00:00.000000+00:00",
      "provider_slug": "github",
      "source_method": "JSON_API",
      "source_url": "https://api.github.com/users/alice"
    },
    {
      "value": "https://github.com/alice",
      "original": "https://github.com/alice",
      "source": "html_jsonld.sameAs",
      "observed_at": "2026-09-01T12:00:00.000000+00:00",
      "provider_slug": "github",
      "source_method": "HTML",
      "source_url": "https://api.github.com/users/alice"
    }
  ]
}
```

Regras:

- Um extrator posterior **acrescenta** itens; ele nunca reescreve a proveniência dos itens já registrados.
- A lista de compatibilidade `value` mantém a ordem de primeira aparição e a deduplicação exata de strings. O **mesmo** valor observado por dois extratores aparece **uma vez** em `value` e **duas vezes** em `items` — são duas observações do mesmo fato, e nenhuma das duas é apagada.
- O mesmo valor pela mesma origem duas vezes é uma única observação (deduplicada por `value` + `source` + `source_method`).
- Se todos os itens compartilham a mesma origem, o nível da linha repete essa origem exata (`source` e `source_method` inalterados). Caso contrário, `source` passa a ser `"multiple"`, `source_method` passa a ser `MIXED` — que **não** é uma origem de extração, e sim um marcador de linha — e as demais chaves compartilhadas são omitidas em vez de adivinhadas. `items` é a autoridade nesse caso.
- **`MIXED` exige mais de um método conhecido.** O marcador afirma que os itens chegaram por **dois ou mais métodos de aquisição distintos e conhecidos**. Se o `source_method` de qualquer item for desconhecido, o método da linha é **omitido** em vez de declarado `MIXED`: proveniência desconhecida não prova uma segunda origem, e adivinhar o método ausente seria a resposta falsa. Em termos de projeção: um método conhecido compartilhado → esse método; dois ou mais conhecidos → `MIXED`; qualquer desconhecido → nenhum método na linha.
- `source: "multiple"` e `source_method: MIXED` são projeções relacionadas, mas **não são sinônimos**: a primeira descreve heterogeneidade de **extrator**, a segunda heterogeneidade de **método de aquisição**. Uma lista pode ter dois extratores e um só método (`"multiple"` com `HTML`), ou dois extratores e um método desconhecido (`"multiple"` sem método algum).
- `MIXED` é recusado em um **item** e em uma linha **sem** `items`: as origens reais de aquisição são `INPUT`, `JSON_API`, `HTML`, `AUTHENTICATED_PUBLIC` e `DERIVED` (`EXTRACTION_METHODS`). Um item marcado `MIXED` seria o registro autoritativo sem método real de aquisição, e uma linha `MIXED` sem itens não aponta para nada.
- **`source: "multiple"` também exige `items`.** O marcador significa "nenhuma string de origem única descreve todos os membros; a proveniência autoritativa está em `items`". Sem `items` ele aponta para nada — estruturalmente o mesmo problema do `MIXED` sem itens — e a linha é recusada. Só o marcador reservado **exato** participa dessa regra: qualquer outra string de `source` segue livre — `"multiple_source_test"` inclusive. Quando `items` existe, a validação de projeção linha/itens continua sendo a autoridade sobre se `"multiple"` é de fato a projeção correta.
- **O marcador `"multiple"` é de linha, e só de linha.** Um `ObservedItem` **não** pode declarar `source: "multiple"`, exatamente como não pode declarar `source_method: MIXED`: um item *é* um dos membros que o marcador manda inspecionar, então usá-lo seria o registro autoritativo sem nomear extrator algum. Sem essa regra, um único item marcado `"multiple"` fazia `project_items()` projetar uma linha com `source: "multiple"` sem que nenhuma heterogeneidade de extrator tivesse sido provada — a linha impersonava uma agregação de uma observação só. Apenas a string reservada exata é recusada; `ObservedItem.source` segue livre para qualquer outro caminho de extração.
- **Uma linha agregada pode diferir origens de derivação heterogêneas para `items`.** Se **todos** os itens são `DERIVED` mas nomeiam campos de origem **diferentes** (`website`, `avatar_url`), a linha mantém `source_method: DERIVED` — cada item prova isso, então a linha é verdadeira — e **omite** `derived_from`, porque nenhuma origem única descreve a lista e `items` já guarda cada uma exatamente. Repetir a origem de um item para todos seria falso, e apagar o método seria perder um fato provado. A exceção vale **só** para a linha com `items` e **só** quando a projeção dos próprios itens também omite a origem: a validação linha/itens continua fixando todas as outras chaves, então uma linha que apague uma origem compartilhada, ou invente uma que os itens não sustentam, segue recusada. Se os itens divergem também no método, a projeção volta a ser `MIXED` sem `derived_from`, como antes.
- **`INPUT` não pode declarar `source_url`**, nem na linha nem em um item. `INPUT` é entrada do operador, não aquisição de rede: não existe URL de onde ela tenha sido lida. `source_method` e `source_url` são tipados de forma independente, então sem esse invariante um dado serializado poderia registrar **proveniência de rede fabricada** dentro do contrato validado. Qualquer `source_url` presente é recusado, inclusive string vazia — uma URL em branco não é proveniência mais fraca, é proveniência que essa observação não pode ter. As origens reais de rede (`JSON_API`, `HTML`, `AUTHENTICATED_PUBLIC`, `DERIVED`) seguem carregando a URL normalmente, e o comportamento de extração não mudou: `enrich_profile()` já emitia `INPUT` sem URL.
- `observed_at` da linha é a observação mais recente entre os itens; cada item preserva a sua.
- **"Mais recente" é o instante absoluto, não o relógio de parede.** A escolha do item mais novo compara instantes absolutos, porque dois timestamps com fuso podem ter os mesmos dígitos locais e representar instantes diferentes — 01:30 acontece duas vezes na volta do horário de verão, e a segunda ocorrência é uma hora mais nova. A comparação usa uma chave numérica derivada da posição no calendário local menos o deslocamento UTC, e não a conversão do timestamp para um `datetime` em UTC: assim ela vale em todo o intervalo de datas com fuso que o contrato aceita, inclusive para deslocamentos cujo instante equivalente em UTC cairia fora dos anos 1–9999. A chave serve **apenas para comparar**: a linha guarda o timestamp do item selecionado exatamente como ele foi observado, com o deslocamento original. Uma linha projetada de um item marcado `-05:00` continua serializando `-05:00`, e nada é normalizado para `+00:00` por causa da comparação.
- **A consistência linha/itens de `observed_at` também compara instantes.** Dois deslocamentos que nomeiam o mesmo momento (`2026-11-01T01:30:00-05:00` no item e `2026-11-01T06:30:00+00:00` na linha) descrevem a mesma observação e são aceitos, sem reescrever nenhuma das duas representações; dois timestamps com o mesmo relógio local que nomeiam momentos diferentes são recusados. Vale igualmente nas bordas do intervalo, onde não existe `datetime` em UTC que nomeie aquele instante. Proveniência temporal é o instante, não a grafia do deslocamento. As demais chaves da projeção seguem com igualdade exata.
- **A linha não pode contradizer seus itens.** Uma linha que carrega `items` só é válida se `value`, `original`, `source`, `observed_at`, `provider_slug`, `source_method`, `source_url` e `derived_from` forem exatamente a projeção que aqueles itens produzem (`project_items()`) — com `observed_at` comparado por instante, conforme a regra acima. Sem essa validação, uma linha serializada poderia declarar um valor ou uma origem que nenhum item observou, e `flatten_observed()` / a apresentação leriam uma evidência diferente de consumidores que tratam `items` como autoridade. Uma linha de lista legada não tem `items` e não é afetada; `rejected_by` descreve o campo, não os itens, e por isso não entra na projeção.
- **`rejected_by` é de campo, não de item.** `ObservedField` carrega a chave; `ObservedItem` **não a tem**, e um item serializado que a traga é recusado como chave extra (`extra="forbid"`) — recusado por ser metadado fora de lugar, e não por a linha contradizer seus itens. Sem isso, a lista de compatibilidade `value` poderia expor um item como aceito enquanto a proveniência desse mesmo item se diz rejeitada. B2-03A **não** define estados de item aceito/rejeitado, **não** filtra itens por rejeição e **não** emite observações rejeitadas: `ObservedField.rejected_by` segue reservado para B2-03B.

### Compatibilidade

- Linhas antigas com apenas as quatro chaves originais continuam válidas, escalares e de lista. `parse_observed()` aceita-as e interpreta um `observed_at` sem fuso como UTC, em vez de rejeitá-lo. Uma linha de lista legada simplesmente não tem `items`.
- Chaves aditivas são opcionais: `None` é excluído da serialização e nunca aparece como string vazia.
- Nenhuma migração de banco: `Finding.data` já é uma coluna JSON.
- Consumidores que leem apenas `value`, `original`, `source` e `observed_at` seguem funcionando sem alteração — inclusive `flatten_observed()` e `observed_profile_fields()`, que ignoram `items`. **A correlação ainda não foi migrada para o modelo em B2-03A** — isso é B2-03B, que passa a consumir `items` para explicar evidência de link por item.
- `original` de um item repete hoje o próprio valor normalizado, exatamente como a linha de lista já fazia antes deste contrato. Preservar o texto bruto pré-normalização por item é escopo de B2-03B.
- Essa convenção é local ao enriquecimento de perfis de username; outros módulos gravam valores diretamente em `Finding.data`. Veja [Resultados & Status](../results.md).
