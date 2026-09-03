# SPECTRE OSINT

<div class="spectre-banner-wrap">
  <img src="assets/brand/spectre-banner.svg" alt="SPECTRE OSINT Banner" width="100%">
</div>

Bem-vindo à documentação oficial do **SPECTRE OSINT**, uma workstation de linha de comando (CLI-first) projetada para coleta, estruturação e correlação passiva de pegadas digitais públicas.

---

## 🧭 O que você deseja fazer?

<div class="spectre-card-grid">
  <a href="getting-started/" class="spectre-card">
    <div>
      <h3>🚀 Início Rápido</h3>
      <p>Aprenda a instalar o SPECTRE e execute sua primeira investigação em menos de 2 minutos.</p>
    </div>
  </a>

  <a href="installation/" class="spectre-card">
    <div>
      <h3>💻 Guia de Instalação</h3>
      <p>Instruções para Windows (PowerShell), Debian/Ubuntu/Kali, Arch Linux e macOS.</p>
    </div>
  </a>

  <a href="commands/" class="spectre-card">
    <div>
      <h3>📖 Manual de Comandos</h3>
      <p>Referência prática e organizada dos comandos disponíveis na CLI, com exemplos e notas operacionais.</p>
    </div>
  </a>

  <a href="examples/" class="spectre-card">
    <div>
      <h3>🔬 Exemplos Práticos</h3>
      <p>Cenários investigativos com alvos sintéticos: usernames, domínios, e-mails e busca pública.</p>
    </div>
  </a>

  <a href="results/" class="spectre-card">
    <div>
      <h3>📊 Resultados & Status</h3>
      <p>Entenda o significado de cada status (CONFIRMED, LIKELY, NOT_FOUND, etc.) e a proveniência dos dados.</p>
    </div>
  </a>

  <a href="concepts/evidence/" class="spectre-card">
    <div>
      <h3>🧠 Modelo de Evidências</h3>
      <p>Os quatro invariantes probatórios e como evitamos transformar suposições em fatos.</p>
    </div>
  </a>

  <a href="technical/architecture/" class="spectre-card">
    <div>
      <h3>🏗️ Arquitetura Técnica</h3>
      <p>Estrutura interna, mapa de componentes, Site Catalog 2.0 e pipeline de busca.</p>
    </div>
  </a>

  <a href="en/" class="spectre-card">
    <div>
      <h3>🇺🇸 English Docs</h3>
      <p>Documentation overview, quick start, and CLI reference in English.</p>
    </div>
  </a>
</div>

---

## ⚡ Exemplo em 30 Segundos

```bash
# Diagnosticar o ambiente local
spectre doctor

# Investigar um username em dezenas de plataformas públicas
spectre username alice_osint

# Investigação completa com correlação e geração de relatório HTML
spectre investigate alice_osint --email alice@example.com
```

---

## 🛡️ Pilares Fundamentais

<div class="spectre-invariants-box">
  <h4>Regras de Controle Probatório</h4>
  <ul class="spectre-invariants-list">
    <li class="no">✖ HTTP 200 ≠ Perfil Confirmado</li>
    <li class="no">✖ Mesmo Username ≠ Mesma Pessoa</li>
    <li class="no">✖ Entrada do Analista ≠ Evidência Observada</li>
    <li class="no">✖ Candidato de Busca ≠ Perfil Confirmado</li>
    <li class="yes">✔ Proveniência Explícita de Origem</li>
    <li class="yes">✔ Correlação Conservadora de Perfis</li>
  </ul>
</div>

- **CLI-First:** Otimizado para linha de comando, automação de terminal e esteiras de SOC.
- **Passive-First:** Coleta somente informações públicas disponíveis na internet.
- **Armazenamento Local:** Banco SQLite, logs e relatórios residem sob controle exclusivo no seu computador.
