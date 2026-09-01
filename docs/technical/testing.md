# Diretrizes de Testes & Qualidade

Instruções, fluxos de validação e regras fundamentais para execução da suíte de testes automatizados do SPECTRE.

*Regra de ouro: Não afirme que "os testes passaram" sem ter executado o comando correspondente neste repositório.*

---

## 1. Comandos de Teste Existentes

```bash
# Suíte padrão (unitária e integração)
pytest
# Ou modo conciso
pytest -q

# Verificação de lint, tipos e integridade de dependências
ruff check spectre_osint tests
mypy spectre_osint
pip check

# Verificação de vulnerabilidades de dependências (no extra dev e CI)
pip-audit

# Diagnóstico de instalação (sem investigações e sem impressão de segredos)
spectre --version          # Confirma versão 0.1.0b1
spectre doctor
spectre doctor --json

# Smoke test de empacotamento: venv temporário, pip install -e ., help + doctor, remoção
bash scripts/smoke_install.sh

# Checklist local pré-tag (não cria tag nem faz push; valida 0.1.0b1)
bash scripts/release_check.sh
```

- **Integração Contínua (CI):** Executada em `.github/workflows/ci.yml` nas versões **Python 3.12** e **Python 3.13** com `pip check`, `pytest` com cobertura, `ruff`, `mypy` e `pip-audit`.
- **Instalação de Desenvolvimento:** `pip install -e ".[dev]"`.

---

## 2. Níveis de Validação

### Validação Rápida (Quick Validation)
Utilize quando a alteração for restrita à documentação ou a um módulo minúsculo e isolado:
```bash
git diff --check
ruff check spectre_osint tests
```
*Se apenas `docs/` ou `README.md` foi alterado, `git diff --check` é o mínimo indispensável. Execute o `pytest` se tocou em `spectre_osint/` ou `tests/`.*

### Validação por Módulo
Execute os testes que cobrem o código alterado:
```bash
pytest tests/test_doctor.py -q
pytest tests/test_search_intelligence.py -q
pytest tests/test_username_identity.py -q
pytest tests/test_username_json_flat.py -q
pytest tests/test_username_json_nested.py -q
```
Em seguida, execute `ruff` e `mypy`.

### Validação Completa de Release
```bash
pytest -q
ruff check spectre_osint tests
mypy spectre_osint
pip check
pip-audit
bash scripts/smoke_install.sh
bash scripts/release_check.sh
spectre doctor
git status
git ls-files | grep -Ei '\.(db|sqlite3?)$|storage_state|\.env$' && echo FAIL
```

---

## 3. Regras Fundamentais para Testes

1. **100% Offline e Sintético:** Fixtures utilizam exclusivamente dados sintéticos (`alice_osint`, `Alice Example`). Testes nunca dependem de contas pessoais reais ou de tráfego de rede ao vivo.
2. **Sem Credenciais Reais:** Testes não exigem chaves de API reais nem logins reais de navegador (backend `fake` em `conftest.py`).
3. **Expectativas do Doctor:** Testes do `spectre doctor` asseguram que segredos nunca sejam impressos e que investigações nunca sejam iniciadas.
4. **Sem Delays de Backoff:** Fixtures utilizam `Settings(ssrf_enabled=False, http_max_retries=1)` para desativar esperas desnecessárias de retry em testes de status.
5. **Não Mascarar Erros:** Preserve a suíte existente; nunca delete testes com falha apenas para "ficar verde".
