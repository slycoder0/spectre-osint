# Exemplos Práticos de Investigação

Nesta página, apresentamos exemplos práticos de fluxos investigativos com o SPECTRE OSINT, utilizando exclusivamente identificadores sintéticos e domínios de documentação (`example.com`, `alice_osint`, IPs RFC 5737).

---

## 1. Investigação Básica de Username

### Cenário
Você recebeu um handle suspeito (`alice_osint`) e precisa mapear em quais plataformas públicas esse nome possui perfis ativos.

### Execução
```bash
spectre username alice_osint
```

### O que esperar
O SPECTRE executa a varredura contra as plataformas do Site Catalog. No terminal, você verá uma tabela com:
- **Plataformas com perfil confirmado** (ex: GitHub, Reddit, Keybase).
- **Metadados extraídos** (ex: Nome de exibição, Avatar, Biografia, Links informados na bio).
- **Status detalhado** de cada plataforma (CONFIRMED, NOT_FOUND, LOGIN_REQUIRED, BLOCKED).

---

## 2. Investigação de Username com Pistas e Correlação

### Cenário
Além do handle principal `alice_osint`, o analista sabe que o alvo também utiliza o alias `alice-sec`, possui o e-mail de contato `alice@example.com` e o blog `https://alice.example`.

### Execução
```bash
spectre investigate alice_osint \
  --alias alice-sec \
  --name "Alice Example" \
  --email alice@example.com \
  --website "https://alice.example"
```

### O que o SPECTRE faz:
1. **Varredura de Catálogo:** Consulta ambos os usernames (`alice_osint` e `alice-sec`).
2. **Busca e Menções Públicas:** Consulta motores de busca para descobrir menções associadas ao e-mail e website.
3. **Classificação de Novidade:** Identifica novos indicadores encontrados como `NOVEL` ou `DERIVED`.
4. **Motor de Correlação:** Compara pares de perfis encontrados calculando pontuações com base em URLs de avatar normalizadas, links recíprocos e biografias.
5. **Geração de Dossiê:** Cria o arquivo `reports/case-username-alice_osint-....html` contendo o grafo interativo e gavetas de proveniência de evidências. O grafo é renderizado pela biblioteca Cytoscape carregada de `unpkg.com`, portanto exige internet no momento da abertura; sem rede, o restante do dossiê continua legível.

---

## 3. Investigação de Infraestrutura e Domínio

### Cenário
Investigar a pegada pública de um domínio suspeito (`example.com`) e identificar servidores de e-mail, nomes de subdomínios via Certificate Transparency e dados de registro RDAP.

### Execução
```bash
spectre domain example.com --auto-pivot --depth 2
```

### Resultados Obtidos:
- **DNS:** Registros A, AAAA, MX, TXT, NS e CNAME.
- **Certificate Transparency (crt.sh):** Lista de subdomínios históricos que emitiram certificados SSL/TLS.
- **RDAP / Whois:** Entidades registrantes e servidores de nomes autoritativos.
- **Pivots Automáticos:** Quando `--auto-pivot` está ativo, o SPECTRE inicia investigações secundárias sobre os endereços IP dos registros A/MX descobertos.

---

## 4. Inspeção de Redes Sociais com Login-Wall

### Cenário
A plataforma Instagram exige autenticação para visualizar biografias e posts públicos. O operador deseja utilizar sua própria conta dedicada de pesquisa para inspecionar perfis sem que o SPECTRE armazene senhas.

### Execução Passo a Passo:

#### Passo 1: Iniciar login manual
```bash
spectre auth login instagram
```
Uma janela do Google Chrome/Chromium será aberta na página oficial de login do Instagram. Faça login normalmente (inclusive com 2FA se solicitado). O SPECTRE monitora automaticamente o estado da sessão e conclui o fluxo quando a autenticação é detectada ou quando o tempo limite é atingido; não é necessário pressionar Enter no terminal.

#### Passo 2: Verificar o status da sessão
```bash
spectre auth status
```

#### Passo 3: Executar a investigação
```bash
spectre username alice_osint
```
O SPECTRE utilizará o contexto isolado do navegador para consultar a página pública do Instagram e extrair metadados observados com status `LIKELY` e confiança `HIGH`.

*Nota: A autenticação permite observar metadados públicos atrás do login-wall; ela não transforma o perfil automaticamente em CONFIRMED.*

#### Passo 4: Encerrar a sessão ao concluir o caso
```bash
spectre auth logout instagram
```

---

## 5. Exportação e Regeneração de Relatórios

```bash
# Exportar todos os formatos disponíveis da última investigação
spectre report --format all
```

Formatos gerados:
- `.html`: Relatório visual interativo completo.
- `.json`: Dados estruturados para integração em pipelines e SIEM.
- `.md`: Resumo legível em Markdown.
- `.csv`: Tabelas de entidades e relacionamentos para planilhas.
- `.graphml`: Grafo de relacionamentos para ferramentas de análise de vínculos.
