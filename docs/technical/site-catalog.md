# Site Catalog 2.0

O **Site Catalog 2.0** é o catálogo tipado de plataformas públicas utilizado pelo módulo de username do SPECTRE.

---

## 1. Definição do Catálogo (`data/sites.yaml`)

O catálogo contém atualmente a especificação determinística de 57 provedores públicos. Cada entrada segue o esquema validado pelo Pydantic `SiteDefinition`:

```yaml
  - name: GitHub
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

## 2. Métodos de Verificação (`check_method`)

1. **`json_api` (APIs Estruturadas JSON):**
   - Utiliza endpoints públicos que retornam payloads JSON estruturados.
   - **Predicado de Identidade:** O campo configurado em `json_id_field` (suportando caminhos aninhados com notação de ponto, como `them.0.id` ou `data.name`) deve resolver para um **valor escalar de identidade não-vazio e significativo** para que o resultado seja classificado como `CONFIRMED`.
2. **`generic_html` (Assinaturas HTML):**
   - Utiliza expressões regulares para detectar marcadores afirmativos de presença e assinaturas de Soft-404.
3. **`login_wall` (Plataformas com Barreira de Autenticação):**
   - Plataformas que exigem sessão conectada para visualização de metadados públicos, operando via `AUTHENTICATED_PUBLIC`.

---

## 3. Predicado de Identidade JSON

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

## 4. Testes Offline Determinísticos

Todos os provedores de API JSON possuem cobertura de testes 100% offline via `httpx.MockTransport`, validando payloads positivos, ausência de campo e status de erro sem requisições à internet.
