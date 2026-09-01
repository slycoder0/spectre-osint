# Interface Web Legada (Depreciação)

<div class="spectre-deprecation-callout">
  <h4>⚠️ Aviso de Depreciação</h4>
  <p>A interface Web/Dashboard local (<code>spectre web</code> e <code>spectre dashboard</code>) está <strong>depreciada</strong> e tem remoção planejada para o milestone <strong>0.1.0b2</strong>.</p>
</div>

---

## Direção do Produto: CLI-First

O SPECTRE OSINT consolida sua arquitetura exclusivamente em torno de ferramentas de linha de comando (CLI-first), dados estruturados em JSON e relatórios estáticos em HTML standalone.

### Motivos da Descontinuação
1. **Velocidade e Automação:** A CLI permite execução instantânea e integração em esteiras de automação e SOC sem dependências de servidores em background.
2. **Segurança Local:** Reduz a superfície de ataque ao eliminar servidores HTTP rodando localmente.
3. **Relatórios Superiores Standalone:** Os relatórios HTML gerados contêm visualização em grafo D3 e tabelas interativas completas sem depender de um servidor FastAPI ativo.

---

## Uso em Modo de Manutenção

Caso necessário durante a transição, a interface legada pode ser iniciada:

```bash
spectre web
# ou o alias:
spectre dashboard
```

- **Bind padrão:** O servidor vincula-se ao endereço local `127.0.0.1:8000`.
- **Opções:** Aceita `--host` e `--port`. A vinculação a endereços externos (não-loopback) exige opt-in explícito do operador com `SPECTRE_ALLOW_PUBLIC_BIND=true`.
