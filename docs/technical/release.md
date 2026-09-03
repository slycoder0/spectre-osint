# Processo de Release & Versionamento

O SPECTRE encontra-se em **beta `0.1.0b1` (lançado)**. Tag `0.1.0b1` publicada.

---

## 1. Canal de Versões

```text
0.1.0b1 (lançado)  →  subsequentes betas  →  estável
```

O arquivo `CHANGELOG.md` segue o padrão *Keep a Changelog*. Enquanto uma tag não existir, o trabalho permanece sob a seção `[Unreleased]`.

- **Fonte da Versão:** `spectre_osint/__init__.py` → `__version__` (versão dinâmica setuptools em `pyproject.toml`).

---

## 2. Processo de Release (Executar Apenas Sob Demanda)

1. **Preflight:**
   - `git status` limpo.
   - Revisão do checklist de marcos e prontidão de release.
   - Confirmar ausência de `.env`, `*.db`, `storage_state.json` ou relatórios reais rastreados no git.
   - `spectre doctor` com status pronto (sem `ACTION REQUIRED` em instalação limpa).
2. **Version Bump (Commit Explícito):**
   - Atualizar `__version__ = "0.1.0b2"` (ou versão alvo).
   - Atualizar asserções de versão em `scripts/smoke_install.sh` e `scripts/release_check.sh`.
   - O classificador em `pyproject.toml` pode permanecer `Alpha` ou `Beta` até a versão estável.
3. **CHANGELOG:**
   - Adicionar `## [0.1.0bX] - AAAA-MM-DD` a partir do conteúdo de `[Unreleased]`.
   - Manter uma nova seção `[Unreleased]` vazia.
4. **Testes & Segurança:**
   - Execução de `pytest`, `ruff check .`, `mypy spectre_osint`, `pip check`, `pip-audit`.
   - `bash scripts/smoke_install.sh`.
   - `bash scripts/release_check.sh` (valida a versão declarada).
5. **Metadados de Documentação.**
6. **Tag (Apenas Sob Solicitação Explícita):**
   - Criar tag anotada no commit de bump com a versão correspondente:
     ```bash
     git tag -a <VERSION> -m "Release <VERSION>"
     ```
     (Exemplo para release subsequente: `git tag -a 0.1.0b2 -m "Release 0.1.0b2"`).
7. **Push (Apenas Sob Solicitação Explícita):**
   - Push da branch `main` e em seguida das tags.
8. **GitHub Release (Apenas Sob Solicitação Explícita):**
   - Criada a partir da tag correspondente; nunca anexar relatórios reais, arquivos `.env` ou sessões.

---

## 3. Rollback & Recuperação de Falhas

Caso uma tag ou release com problemas seja publicada:

- **Não force o push na `main`** (`git push --force`) a menos que o operador ordene explicitamente uma reescrita de histórico (padrão: nunca reescrever).
- Desmarque/arquive a GitHub Release como rascunho se a interface permitir.
- Publique um commit de correção subsequente e crie uma nova tag (ex: `0.1.0b2`).
- **Se um segredo foi parar no git:** Rotacione o segredo imediatamente; trate o histórico como comprometido; não tente "consertar" apenas deletando o arquivo na `main`.
- Se `release_check.sh` ou a CI falhar após o bump, **não crie a tag**. Reverta o commit de bump apenas se ainda não tiver sido feito push (`git reset --soft HEAD~1` localmente, aprovado pelo operador).

---

## 4. Scripts de Garantia no Repositório

- `scripts/smoke_install.sh` — Instalação em ambiente venv limpo + verificação de `--help` e `spectre doctor`.
- `scripts/release_check.sh` — Validação de presença de docs obrigatórios, pytest, ruff, mypy, pip check, pinagem de versão e verificação de artefatos rastreados proibidos.
- Fluxo de CI no GitHub Actions como segundo portão após push.
