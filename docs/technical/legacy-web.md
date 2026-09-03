# Interface Web Legada (Removida)

<div class="spectre-deprecation-callout">
  <h4>⚠️ Registro Histórico de Remoção</h4>
  <p>A interface Web/Dashboard local (<code>spectre web</code> e <code>spectre dashboard</code>) foi <strong>removida</strong> no milestone de desenvolvimento <strong>0.1.0b2</strong>. Esta página é mantida apenas como registro histórico da remoção; os comandos não existem mais.</p>
</div>

---

## Direção do Produto: CLI-First

O SPECTRE OSINT consolida sua arquitetura exclusivamente em torno de ferramentas de linha de comando (CLI-first), dados estruturados em JSON e relatórios estáticos em HTML de arquivo único.

### Motivos da Descontinuação
1. **Velocidade e Automação:** A CLI permite execução instantânea e integração em esteiras de automação e SOC sem dependências de servidores em background.
2. **Segurança Local:** Reduz a superfície de ataque ao eliminar servidores HTTP rodando localmente.
3. **Relatórios em Arquivo Único:** Os relatórios HTML gerados são arquivos únicos que já embutem no próprio arquivo os dados exibidos (achados, tabelas e o payload do grafo), sem depender de um servidor ativo.

!!! warning "Dependência de rede no grafo do relatório HTML"
    A renderização interativa do grafo carrega a biblioteca Cytoscape de `https://unpkg.com/cytoscape@3.30.2` no momento em que o relatório é aberto. Consequências: abrir o relatório com internet gera uma requisição a esse terceiro; em uso offline ou air-gapped o grafo não é renderizado, embora o restante do relatório (achados, tabelas e proveniência) continue legível, pois já está embutido no arquivo.

---

## O Que Foi Removido no 0.1.0b2

| Item removido | Detalhe |
| :--- | :--- |
| Comandos CLI | `spectre web` e o alias `spectre dashboard` |
| Pacote de runtime | `spectre_osint/web/` (aplicação FastAPI, templates Jinja2, assets estáticos, fontes empacotadas, catálogos de i18n, executor de jobs em memória e a visão de grafo do dashboard) |
| Dependências de runtime | `fastapi`, `starlette`, `uvicorn[standard]`, `python-multipart` |
| Configuração | `SPECTRE_WEB_HOST` / `Settings.web_host` e `SPECTRE_ALLOW_PUBLIC_BIND` / `Settings.allow_public_bind` |
| Diagnóstico | A verificação `Bind address` do `spectre doctor` |
| Plumbing de container | `EXPOSE 8000`, a porta publicada em loopback e o `command: ["web", ...]` do `docker-compose.yml` |

Invocar `spectre web` ou `spectre dashboard` agora falha como comando desconhecido, com código de saída diferente de zero.

Nenhum alias de compatibilidade foi mantido para as variáveis removidas. `Settings` usa `extra="ignore"`, portanto um `SPECTRE_WEB_HOST` remanescente em um `.env` antigo é simplesmente ignorado, sem erro.

As variáveis `SPECTRE_SSRF_ENABLED` e `SPECTRE_ALLOW_PRIVATE_TARGETS` **não** foram afetadas: elas governam a segurança de requisições de saída, não um socket de escuta.

---

## O Que Usar Agora

O fluxo de investigação é a CLI, e o artefato de revisão é o relatório em arquivo único:

```bash
# Investigação completa com correlação, grafo e relatório HTML
spectre investigate alice_osint

# Regerar artefatos da última execução concluída
spectre report --format html
```

Consulte [Comandos](../commands.md) para a referência completa da CLI e [Arquitetura](architecture.md) para o mapa de pacotes atual.

A semântica de evidências permaneceu inalterada pela remoção: `PERFIL EXISTE != MESMA PESSOA`, `ENTRADA != EVIDÊNCIA`, `HTTP 200 != CONFIRMADO` e `CANDIDATO != IDENTIDADE CONFIRMADA` continuam valendo exatamente como antes.
