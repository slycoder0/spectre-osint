# Site Catalog 2.0

O **Site Catalog 2.0** é o catálogo tipado de plataformas públicas utilizado pelo módulo de username do SPECTRE.

---

## 1. Definição do Catálogo (`data/sites.yaml`)

O catálogo contém atualmente a especificação determinística de 57 provedores públicos. Cada entrada segue o esquema validado pelo Pydantic `SiteDefinition`:

```yaml
  - name: GitHub
    slug: github
    category: Development
    profile_url: "https://github.com/{username}"
    check_url: "https://api.github.com/users/{username}"
    check_method: json_api
    json_id_field: login
    display_name_fields: [name, login]
    website_fields: [blog]
    bio_field: bio
    avatar_field: avatar_url
    location_field: location
    expected_status: [200]
    not_found_status: [404]
    enabled: true
    confidence_strategy: explicit_api
    rate_limit: 0.5
    notes: Public users API. Token optional for quota.
```

---

## 2. Identidade do Catálogo (`slug`)

Toda entrada de produção declara um `slug` **explícito e estável**. O `slug` é o identificador do provedor no catálogo: é a chave de `SiteCatalog.get_by_slug()`, do índice interno de unicidade e do campo `slug` exportado por `to_dict()` / `load_sites()`.

- **`name` é um rótulo de apresentação**, não um identificador. Renomear o `name` de um provedor não altera o `slug` declarado.
- **`slug` é estável**: formato canônico `^[a-z0-9_]+$` (ASCII minúsculo, dígitos e sublinhados).
- **Validação de produção** (`load_catalog()`, o carregador usado pelo runtime) rejeita:
  - `slug` ausente;
  - `slug` vazio ou composto apenas por espaços;
  - `slug` fora do formato canônico;
  - `slug` duplicado entre entradas;
  - `name` duplicado (colisão sem diferenciação de maiúsculas/minúsculas).

Nenhuma entrada de produção pode omitir `slug` e receber silenciosamente um identificador derivado do nome de exibição.

### Compatibilidade com definições customizadas e legadas

A derivação `slugify_name(name)` continua existindo apenas como *fallback* de compatibilidade para definições **não-produção** — catálogos customizados ou legados anteriores ao contrato explícito. Ela é alcançada por:

- `SiteCatalog.from_dict()` / `SiteCatalog.from_yaml_file()` / `SiteDefinition.model_validate()`, que permanecem tolerantes por padrão;
- `load_catalog(caminho, require_explicit_slug=False)`, a saída explícita para carregar um arquivo de catálogo anterior ao B2-02B.

O padrão de `load_catalog()` é `require_explicit_slug=True`. O cache do catálogo é indexado por caminho **e** por modo de validação, de modo que um catálogo carregado em modo tolerante nunca é servido a um chamador estrito.

---

## 3. Métodos de Verificação (`check_method`)

1. **`json_api` (APIs Estruturadas JSON):**
   - Utiliza endpoints públicos que retornam payloads JSON estruturados.
   - **Predicado de Identidade:** O campo configurado em `json_id_field` (suportando caminhos aninhados com notação de ponto, como `them.0.id` ou `data.name`) deve resolver para um **valor escalar de identidade não-vazio e significativo** para que o resultado seja classificado como `CONFIRMED`.
2. **`generic_html` (Assinaturas HTML):**
   - Utiliza expressões regulares para detectar marcadores afirmativos de presença e assinaturas de Soft-404.
3. **`login_wall` (Plataformas com Barreira de Autenticação):**
   - Plataformas que exigem sessão conectada para visualização de metadados públicos, operando via `AUTHENTICATED_PUBLIC`.

---

## 4. Predicado de Identidade JSON

No motor central (`engine.py`), a confirmação de provedores JSON obedece à função `_is_meaningful_json_identity`:

```python
def _is_meaningful_json_identity(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, int):
        return True
    return False
```

Rejeita strings vazias, valores booleanos, contêineres vazios e strings compostas apenas por espaços, validando strings preenchidas e identificadores inteiros.

---

## 5. Testes Offline Determinísticos

Todos os provedores de API JSON possuem cobertura de testes 100% offline via `httpx.MockTransport`, validando payloads positivos, ausência de campo e status de erro sem requisições à internet.
