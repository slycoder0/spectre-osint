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

- `value` pode ser uma string ou, para `external_links` / `social_links`, uma lista de strings.
- `source` é derivado do provedor e do caminho de extração — por exemplo `github_api.<campo>` para respostas JSON, `github.username` para o handle normalizado, e `html_og.title`, `html_title`, `html_canonical`, `html_jsonld.<campo>` ou `html_rel_me` para extração de HTML. **Essas strings estão congeladas em B2-03A** e permanecem byte a byte idênticas.
- `observed_at` é serializado com `datetime.isoformat()` (deslocamento `+00:00`), exatamente como antes. Observações novas exigem timestamp com fuso horário.
- Campos vazios são omitidos, e o primeiro valor não-vazio para um campo escalar prevalece (`put` não sobrescreve um campo já preenchido).

### Chaves aditivas de proveniência

| Chave | Significado |
| :--- | :--- |
| `provider_slug` | O `slug` declarado pelo catálogo (contrato explícito de B2-02B). Nunca re-derivado do nome de exibição: renomear um provedor não move seu identificador estável. Ausente quando a chamada não recebe definição de site. |
| `source_method` | Origem da observação: `INPUT` (handle informado pelo operador), `JSON_API`, `HTML`, `AUTHENTICATED_PUBLIC` (mesmos extratores de HTML, porém sobre uma busca com sessão conectada — dado público, nunca acesso privado) ou `DERIVED`. |
| `source_url` | URL de onde o payload foi efetivamente lido (`effective_url` do motor), com fallback para `profile_url`. Omitida em `INPUT`, que não veio de página alguma. |
| `derived_from` | Campo de origem de um valor derivado. Hoje apenas `personal_domain`, com `derived_from="website"`. O cálculo de `personal_domain` não mudou. |
| `rejected_by` | Reservado para B2-03B. **B2-03A não emite observações rejeitadas**; um valor rejeitado continua simplesmente omitido. |

### Compatibilidade

- Linhas antigas com apenas as quatro chaves originais continuam válidas. `parse_observed()` aceita-as e interpreta um `observed_at` sem fuso como UTC, em vez de rejeitá-lo.
- Chaves aditivas são opcionais: `None` é excluído da serialização e nunca aparece como string vazia.
- Nenhuma migração de banco: `Finding.data` já é uma coluna JSON.
- Consumidores que leem apenas `value`, `original`, `source` e `observed_at` seguem funcionando sem alteração. **A correlação ainda não foi migrada para o modelo em B2-03A** — isso é B2-03B.
- Essa convenção é local ao enriquecimento de perfis de username; outros módulos gravam valores diretamente em `Finding.data`. Veja [Resultados & Status](../results.md).
