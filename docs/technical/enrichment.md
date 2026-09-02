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

## 3. Estrutura de Proveniência de Campo Observado

Cada campo emitido por `enrich_profile` é um dicionário simples (não há classe/modelo `ObservedField` no código) e aparece apenas sob `data["observed"]` dos achados do módulo `username`:

```python
{
    "value": "Alice Developer",
    "original": "Alice Developer (@alice_osint) - GitHub",
    "source": "github_api.name",
    "observed_at": "2026-09-01T12:00:00.000000+00:00"
}
```

- `value` pode ser uma string ou, para `external_links` / `social_links`, uma lista de strings.
- `source` é derivado do provedor e do caminho de extração — por exemplo `github_api.<campo>` para respostas JSON, `github.username` para o handle normalizado, e `html_og.title`, `html_title`, `html_canonical`, `html_jsonld.<campo>` ou `html_rel_me` para extração de HTML.
- Campos vazios são omitidos, e o primeiro valor não-vazio para um campo escalar prevalece (`put` não sobrescreve um campo já preenchido).
- Essa convenção é local ao enriquecimento de perfis de username; outros módulos gravam valores diretamente em `Finding.data`. Veja [Resultados & Status](../results.md).
