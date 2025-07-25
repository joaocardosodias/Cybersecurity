# Injeção de Template do Lado do Cliente (CSTI): Uma Análise Aprofundada de Mecanismos, Exploração e Defesa

## Seção 1: Introdução à Injeção de Template em Aplicações Web Modernas

### 1.1 O Papel dos Motores de Template na Geração de Conteúdo Dinâmico

Motores de template são fundamentais no desenvolvimento web, separando a lógica de apresentação (HTML) da lógica de aplicação (dados). Eles processam templates com *placeholders* (ex.: `{{user.name}}`) e dados dinâmicos para gerar páginas HTML, promovendo código limpo e escalável. Exemplos incluem perfis de redes sociais, onde a estrutura é estática, mas dados como nome e foto são dinâmicos.

A renderização pode ocorrer no servidor (*server-side*) ou no cliente (*client-side*). No *client-side*, o servidor envia templates e dados JSON, e o JavaScript no navegador realiza a renderização. A ascensão de *Single-Page Applications* (SPAs) com frameworks como AngularJS, React e Vue.js transferiu a renderização para o cliente, ampliando a superfície de ataque e introduzindo a **Injeção de Template do Lado do Cliente (CSTI)**.

### 1.2 Definição da Classe de Vulnerabilidade: Injeção de Template

A **Injeção de Template** ocorre quando entradas de usuários não sanitizadas são processadas como código por um motor de template, em vez de dados literais. Classificada como **CWE-1336** (Neutralização Imprópria de Expressões) e **CWE-94** (Injeção de Código), permite a execução de diretivas arbitrárias. Um exemplo é injetar `{{7*7}}` em um campo como `Olá, {{nome}}`. Se renderizado como `Olá, 49`, indica que o motor avalia a entrada, confirmando a vulnerabilidade.

## Seção 2: A Anatomia da Injeção de Template: CSTI vs. SSTI

### 2.1 Injeção de Template do Lado do Servidor (SSTI)

A **SSTI** ocorre quando entradas são avaliadas no servidor, podendo levar a **Execução Remota de Código (RCE)**. Motores como Jinja2 (Python), Twig (PHP) e FreeMarker (Java) permitem acessar variáveis de ambiente ou arquivos (ex.: `{{config.items()}}` no Flask expõe chaves de API). A severidade é **Crítica**, com riscos de comprometimento total do servidor.

### 2.2 Injeção de Template do Lado do Cliente (CSTI)

A **CSTI** ocorre no navegador, usando frameworks como AngularJS, Vue.js ou Handlebars, resultando principalmente em **Cross-Site Scripting (XSS)**. O atacante injeta expressões (ex.: `{{meu_payload_javascript}}`) que executam JavaScript no contexto do domínio vulnerável. Consequências incluem:

- **Roubo de Sessão**: Acesso a cookies sem `HttpOnly`.
- **Captura de Credenciais**: Injeção de formulários falsos ou *keyloggers*.
- **Ações Não Autorizadas**: Pedidos em nome da vítima.
- **Manipulação do DOM**: Alteração da página para *phishing*.

A CSTI é classificada como **Alta**, mas menos grave que a SSTI, focando no comprometimento do cliente.

## Seção 3: Motores de Template do Lado do Cliente: Funcionamento e Superfície de Ataque

### 3.1 Princípios de Funcionamento

- **Ligação de Dados (*Data Binding*)**: Conecta modelo de dados (objeto JavaScript) à interface HTML, atualizando-a dinamicamente.
- **Avaliação de Expressões**: Analisa expressões como `{{user.name}}`, substituindo-as por valores (ex.: `Alice`).
- **Manipulação do DOM**: Atualiza o DOM com resultados, permitindo XSS se expressões maliciosas forem avaliadas.

### 3.2 Análise de Motores Populares

- **AngularJS**: Usa diretivas (`ng-app`) e um *sandbox* (removido na v1.6) que restringia expressões, mas foi contornado repetidamente.
- **Vue.js**: Codifica saídas por padrão, mas diretivas como `v-html` com dados não sanitizados criam vulnerabilidades XSS.
- **Handlebars**: Um motor *logic-less*, codifica saídas em `{{...}}`, mas `{{{...}}}` ou atributos sem aspas permitem XSS.

## Seção 4: Metodologias de Detecção e Identificação de Vulnerabilidades CSTI

### 4.1 Técnicas de Detecção Manual

- **Teste Inicial**: Injetar `{{7*7}}` em parâmetros (ex.: `https://exemplo.com/search?query={{7*7}}`). Se renderizar `49`, indica avaliação de template.
- **Análise de Resposta**: Se `{{7*7}}` for refletido literalmente, a sintaxe pode não ser vulnerável.

### 4.2 Identificação do Motor de Template

- **Teste de Comportamento**: `{{7*'7'}}` retorna `49` em motores JavaScript (CSTI) e `7777777` em Jinja2 (SSTI).
- **Inspeção do DOM**: Identificar `ng-app` (AngularJS), `data-v-...` (Vue.js) ou `handlebars.js` no código-fonte.
- **Sondagem de Objetos**: `{{angular.version}}` revela a versão do AngularJS.

### 4.3 Poliglotas e Ferramentas

- **Poliglotas**: Strings como `${{<%[%'"}}%` provocam erros que identificam o motor.
- **Ferramentas**: Scanners como Acunetix, Qualys ou TInjA automatizam a detecção.

**Tabela 1: Fingerprinting de Motores de Template**

| Passo | Payload | Resposta | Framework |
|-------|---------|----------|-----------|
| 1 | `{{7*7}}` | `49` | Qualquer motor `{{...}}` |
| 2 | `{{7*'7'}}` | `49` | JavaScript (CSTI/Twig) |
| 2 | `{{7*'7'}}` | `7777777` | Jinja2 (SSTI) |
| 3 | `{{constructor}}` | `function Function()` | AngularJS |
| 3 | Inspeção DOM | `ng-app` | AngularJS |
| 3 | Inspeção DOM | `data-v-...` | Vue.js |
| 3 | `{{this.constructor.constructor('alert(1)')()}}` | Alerta executado | AngularJS (<1.6) |

## Seção 5: Exploração Prática de CSTI

### 5.1 AngularJS: Escapando o Sandbox

- **Versões Iniciais (1.0.1-1.1.5)**:
  ```javascript
  {{constructor.constructor('alert(document.cookie)')()}}
  ```
  Acessa `Function` para executar JavaScript.

- **Versões Intermediárias (1.2.0-1.5.8)**:
  ```javascript
  {{'a'.constructor.prototype.charAt=.join; $eval('x=alert(1)');}}
  ```
  Sobrescreve protótipos para contornar o *sandbox*.

### 5.2 Vue.js: Diretivas e mXSS

- **Abuso de Diretivas**:
  ```html
  <p v-show="_c.constructor('alert(1)')()">Click Me</p>
  ```
  Usa `_c` (alias de `createElement`) para executar código.

- **Mutation XSS (mXSS)**: Parsing do Vue transforma HTML inerte em XSS ativo.

### 5.3 Handlebars: Saída Não Codificada

- **Três Chavetas**:
  ```html
  {{{<script>alert(1)</script>}}}
  ```
  Renderiza HTML sem codificação.

- **Atributos Sem Aspas**:
  ```html
  http://a.com/a.png onload=alert(1)
  ```
  Injeta atributos de evento.

**Tabela 2: Payloads de Exploração**

| Framework | Versão | Payload | Notas |
|-----------|--------|---------|-------|
| AngularJS | 1.0.1-1.1.5 | `{{constructor.constructor('alert(1)')()}}` | Acessa `Function` |
| AngularJS | 1.2.0-1.5.8 | `{{'a'.constructor.prototype.charAt=.join; $eval('x=alert(1)');}}` | Contorna *sandbox* |
| Vue.js | 2.x | `<div v-on:click="_c.constructor('alert(1)')()">` | Usa `_c` |
| Handlebars | Todas | `{{{_script_>alert(1)</script>}}}` | Requer `{{{...}}}` |

## Seção 6: Análise de Impacto e Encadeamento

### 6.1 Consequências

- **Roubo de Cookies/Tokens**: Acesso a `document.cookie` ou `localStorage`.
- **Captura de Credenciais**: Formulários falsos ou *keyloggers*.
- **Tomada de Conta**: Alteração de senha/email.

### 6.2 Divulgação de Informações

Extrai dados do DOM ou estado JavaScript (ex.: PII, mensagens privadas).

### 6.3 Encadeamento com CSRF

CSTI contorna tokens anti-CSRF:
1. Injeta payload JavaScript.
2. Extrai token do DOM.
3. Envia pedidos POST autenticados (ex.: `/settings/delete`).

Eleva a severidade de **Alta** para **Crítica**.

## Seção 7: Estratégias de Prevenção e Mitigação

### 7.1 Codificação Segura

- **Inseguro**: `"<div>Olá, " + nome + "</div>"`
- **Seguro**: `"<div>Olá, {{nome}}</div>"` com `{ nome: nome }`

### 7.2 Validação e Sanitização

- Filtrar sintaxes como `{{`, `}}`.
- Usar motores *logic-less* (ex.: Mustache).

### 7.3 Limitações da Codificação de Saída

Codificação HTML não previne CSTI, pois frameworks descodificam antes de avaliar.

### 7.4 Content Security Policy (CSP)

- **`script-src 'self'`**: Bloqueia scripts externos.
- **`'unsafe-eval'`**: Impede `eval()` e `Function`.
- **`nonce`/`hash`**: Permite scripts *inline* seguros.
- **`connect-src 'self'`**: Limita exfiltração de dados.

### 7.5 Endurecimento por Framework

- **AngularJS**: Migrar para Angular moderno, limitar `ng-app`.
- **Vue.js**: Evitar `v-html`, não montar em DOM com conteúdo do servidor.
- **Handlebars**: Evitar `{{{...}}}`, usar `DOMPurify` para HTML.

**Tabela 3: Defesa em Camadas**

| Camada | Técnica | Objetivo | Notas |
|--------|---------|----------|-------|
| Design | Não concatenar entrada em templates | Prevenir injeção | Usar *placeholders* |
| Validação | Sanitizar `{{`, `}}` | Remover vetores | Cuidado com funcionalidades |
| Execução | CSP: `script-src 'self'` | Bloquear scripts | Gerenciar *nonces* |
| Mitigação | CSP: `connect-src 'self'` | Impedir exfiltração | Limitar endpoints |

## Seção 8: Conclusão e Perspectivas Futuras

### 8.1 Sumário

CSTI é uma ameaça significativa em SPAs, resultando em XSS e ataques complexos como contorno de CSRF. A defesa exige separação de código e dados, validação rigorosa e CSP robusta.

### 8.2 Futuro da Segurança de Templates

As frameworks de cliente mais recentes, como as versões modernas de Vue, React e Angular (pós-AngularJS), demonstram uma maior consciência de segurança, aprendendo com os erros do passado. A tendência é para modelos de segurança mais explícitos e seguros por defeito, movendo-se para longe de mecanismos como o sandbox do AngularJS, que criavam uma falsa sensação de segurança. Em vez disso, a responsabilidade é colocada de forma mais clara no desenvolvedor, com avisos explícitos na documentação sobre práticas perigosas como o uso de v-html em Vue ou dangerouslySetInnerHTML em React.

No entanto, a complexidade crescente das aplicações do lado do cliente e do seu ecossistema de dependências garante que a segurança de templates continuará a ser um campo de batalha ativo. Novos vetores de ataque, como o Mutation XSS, mostram que mesmo as frameworks mais seguras podem ser abusadas de formas imprevistas. A manutenção e atualização contínua das dependências de terceiros é, portanto, mais crítica do que nunca, pois uma vulnerabilidade numa biblioteca de template pode comprometer toda a aplicação. O futuro da segurança de templates dependerá de uma vigilância contínua por parte dos desenvolvedores, de uma investigação proativa por parte da comunidade de segurança, e da adoção generalizada de controlos de segurança no browser, como a CSP, como uma prática padrão e não como uma reflexão tardia.