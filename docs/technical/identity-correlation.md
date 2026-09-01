# Correlação Conservadora de Identidades

O motor de correlação (`spectre_osint/modules/username/identity.py`) avalia a convergência entre pares de perfis públicos `CONFIRMED` e `LIKELY` do catálogo.

---

## 1. Princípios de Correlação

1. **Pesos Determinísticos Fixos:** Os pesos de correspondência são constantes fixas e auditáveis no código.
2. **Mesmo Username como Sinal Fraco:** O reuso de um handle entre plataformas recebe peso baixo propositalmente (`same_username = 6`), prevenindo agrupamentos indevidos.
3. **Sinais Determinísticos Fortes:**
   - Mesmo domínio pessoal (`same_personal_domain = 42`) ou mesma URL pessoal (`same_personal_url = 40`).
   - Links cruzados entre perfis (`cross_profile_link = 38`).
   - Mesmo e-mail público informado na bio (`same_public_email = 35`).
   - Mesmo ID numérico público (`same_public_id = 32`).
   - Mesma URL de avatar normalizada (`same_avatar_url = 18`).
4. **Detecção de Conflitos Biográficos:** Discrepâncias em nomes ou domínios pessoais penalizam severamente a pontuação.

---

## 2. Tabela de Pesos (`WEIGHTS` & `CONFLICTS`)

```python
WEIGHTS = {
    "same_username": 6,
    "same_display_name": 16,
    "similar_bio": 10,
    "same_organization": 10,
    "same_location": 8,
    "same_personal_domain": 42,
    "same_personal_url": 40,
    "cross_profile_link": 38,
    "same_public_id": 32,
    "same_public_email": 35,
    "same_avatar_url": 18,
}

CONFLICTS = {
    "distinct_display_name": -28,
    "distinct_personal_domain": -32,
    "distinct_organization": -18,
    "distinct_location": -12,
    "distinct_public_id": -40,
    "distinct_public_email": -35,
}
```

---

## 3. Faixas de Pontuação (`BANDS`)

| Faixa | Limite Mínimo | Interpretação |
| :--- | :--- | :--- |
| **`STRONG`** | Score >= 80 | Forte convergência de indicadores independentes e links cruzados. |
| **`LIKELY`** | Score >= 60 | Sobreposição pública provável com múltiplos sinais coincidentes. |
| **`POSSIBLE`**| Score >= 30 | Sobreposição pública possível. Requer análise manual do analista. |
| **`LOW`** | Score >= 0 | Sobreposição fraca (pode ser mera coincidência de username). |

*Nota: O limiar para geração de agrupamentos (`CLUSTER_MIN`) é 60.*
