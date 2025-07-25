# Uma Análise Aprofundada de Path Traversal e Técnicas Avançadas de Exploração de Aplicações Web

## Seção 1: Conceitos Fundamentais de Path Traversal

### 1.1. A Mecânica do Directory Traversal: Além da Raiz Web

A vulnerabilidade de **Path Traversal** (ou Directory Traversal) ocorre quando uma aplicação web constrói caminhos para arquivos e diretórios de forma insegura, utilizando entradas controláveis pelo usuário. O objetivo é acessar recursos fora do diretório raiz da web (*web root folder*), que contém o conteúdo público do site.

O ataque utiliza sequências como `../` para navegar para cima na hierarquia de diretórios, permitindo acesso a arquivos sensíveis. Técnicas de ofuscação incluem:

- **Codificação de URL**: `../` pode ser codificado como `%2e%2e%2f`. Dupla codificação (`%252e%252e%252f`) pode contornar validações.
- **Terminadores de Byte Nulo**: Usar `%00` (ex.: `../../../../etc/passwd%00.png`) para enganar validações de extensões, embora menos comum em sistemas modernos.

A determinação do número de `../` necessários é feita por tentativa e erro, com base nas respostas do servidor.

### 1.2. Exploração Clássica: Leitura de Arquivos Sensíveis

A exploração clássica visa arquivos sensíveis, como `/etc/passwd` (UNIX) ou `c:\windows\win.ini` (Windows). Exemplo:

```http
https://exemplo.com.br/get-files.jsp?file=../../../../etc/passwd
```

A aplicação navega para fora do diretório web, expondo o arquivo solicitado.

**Vetores de ataque** não se limitam a parâmetros GET. Cookies também são alvos. Exemplo em PHP:

```php
<?php
   $template = 'blue.php';
   if (isset($_COOKIE['TEMPLATE']))
      $template = $_COOKIE['TEMPLATE'];
   include("/home/users/phpguru/templates/" . $template);
?>
```

**Requisição maliciosa**:

```http
GET /vulnerable.php HTTP/1.0
Cookie: TEMPLATE=../../../../../../../../../etc/passwd
```

Isso faz o servidor incluir `/etc/passwd`. Caminhos absolutos (ex.: `?f=/etc/passwd`) também são exploráveis se a validação for fraca.

### 1.3. Contexto Moderno: Path Traversal como um Componente em Ataques Encadeados

O Path Traversal é cada vez mais usado em cadeias de ataque complexas, como **Web Cache Deception**:

1. O atacante acessa um *endpoint* sensível (ex.: `/profile`) com um caminho como `/profile/..%2fstatic/main.css`.
2. O servidor normaliza o caminho para `/static/main.css`, mas processa `/profile`, retornando dados sensíveis.
3. O cache armazena a resposta sob a chave `/static/main.css`.
4. Outros usuários acessando `/static/main.css` recebem os dados sensíveis.

Essa técnica transforma o Path Traversal em um "gadget" para manipular sistemas distribuídos, ampliando seu impacto em arquiteturas modernas.

## Seção 2: HTTP Request Smuggling: Dessincronizando a Cadeia de Servidores

### 2.1. A Arquitetura da Ambiguidade: Dessincronização Front-End vs. Back-End

O **HTTP Request Smuggling (HRS)** explora discrepâncias na interpretação de requisições HTTP entre servidores front-end (ex.: proxy reverso) e back-end (servidor de aplicação). A reutilização de conexões TCP/TLS (*keep-alive*) permite que uma requisição maliciosa "envenene" o socket, afetando requisições subsequentes.

A dessincronização ocorre quando os servidores discordam sobre os limites de uma requisição, permitindo que o atacante contrabandeie uma requisição maliciosa.

### 2.2. O Conflito Central: Content-Length vs. Transfer-Encoding

A vulnerabilidade surge da ambiguidade entre:

- **Content-Length (CL)**: Especifica o tamanho do corpo em bytes.
- **Transfer-Encoding: chunked (TE)**: Divide o corpo em *chunks*, terminados por `0\r\n\r\n`.

A RFC 7230 determina que o TE prevalece sobre o CL, mas servidores inconsistentes criam dessincronização.

### 2.3. Uma Taxonomia de Ataques de Dessincronização: CL.TE, TE.CL e TE.TE

- **CL.TE**: Front-end usa CL, back-end usa TE. Exemplo:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0
MALICIOUS-REQUEST
```

O front-end lê 13 bytes, o back-end vê o *chunk* `0` como fim, deixando `MALICIOUS-REQUEST` no buffer.

- **TE.CL**: Front-end usa TE, back-end usa CL. Exemplo:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

15
MALICIOUS-REQUEST
0
```

O front-end processa os *chunks*, o back-end lê apenas 3 bytes, deixando o restante no buffer.

- **TE.TE**: Ambos usam TE, mas um é enganado por ofuscação (ex.: `Transfer-Encoding: xchunked`).

**Tabela de Vetores de Ataque**:

| Tipo     | Front-End                | Back-End                 | Condição Chave                                   | Exemplo Simplificado                              |
|----------|--------------------------|--------------------------|--------------------------------------------------|--------------------------------------------------|
| CL.TE    | Usa CL                  | Usa TE                  | CL menor que o corpo real                       | `Content-Length: 13\nTransfer-Encoding: chunked\n\n0\nMALICIOUS` |
| TE.CL    | Usa TE                  | Usa CL                  | CL menor que o corpo processado                 | `Content-Length: 3\nTransfer-Encoding: chunked\n\n15\nMALICIOUS\n0` |
| TE.TE    | Usa TE                  | Usa TE                  | Um servidor ignora TE ofuscado                  | `Transfer-Encoding: xchunked`                   |
| CL.0     | Respeita CL             | Ignora CL               | Back-end trata CL como 0                        | `POST /static/file.js\nContent-Length: X\n\nMALICIOUS` |
| TE.0     | Respeita TE             | Ignora TE               | Discrepância em endpoints específicos            | `OPTIONS /\nTransfer-Encoding: chunked\n\nX\nMALICIOUS\n0` |
| H2.CL    | Encaminha CL (HTTP/2)   | Usa CL (HTTP/1.1)       | CL incorreto no downgrade                       | HTTP/2 com CL incorreto                         |
| H2.TE    | Permite TE (HTTP/2)     | Usa TE (HTTP/1.1)       | TE proibido passa no downgrade                  | HTTP/2 com `Transfer-Encoding: chunked`         |

### 2.4. Vetores Avançados: CL.0, TE.0 e Ataques de Downgrade de HTTP/2

- **CL.0**: O back-end ignora o CL, tratando a requisição como sem corpo, enquanto o front-end a respeita, envenenando o socket.
- **TE.0**: Explorado no Google Cloud com requisições OPTIONS, contrabandeando GETs para vazar tokens de sessão.
- **Ataques de Downgrade de HTTP/2**:
  - **H2.CL**: Front-end não valida CL no downgrade para HTTP/1.1.
  - **H2.TE**: Front-end permite TE (proibido no HTTP/2), causando dessincronização.
  - **Injeção de CRLF**: Inclui `\r\n` em cabeçalhos HTTP/2, interpretados como terminadores no HTTP/1.1.

### 2.5. Detecção e Confirmação: De Sondas de Temporização a Respostas Diferenciais

- **Sondas de Temporização**:
  - **CL.TE**: Requisição com CL truncado causa *timeout* no back-end.
  - **TE.CL**: Requisição com CL maior causa espera no back-end.
  - Testar CL.TE primeiro para evitar envenenamento acidental do socket.

- **Confirmação por Respostas Diferenciais**:
  1. Enviar requisição de ataque para envenenar o socket (ex.: `GET /404`).
  2. Enviar requisição normal em outra conexão.
  3. Uma resposta anômala (ex.: 404 em vez de 200) confirma a vulnerabilidade.

### 2.6. Análise de Impacto

- **Bypass de Controles de Segurança**: Contrabandeia requisições para *endpoints* restritos (ex.: `/admin`).
- **Sequestro de Sessão**: Contrabandeia POSTs parciais para capturar cookies de vítimas.
- **Envenenamento da Fila de Respostas**: Dessincroniza respostas, entregando dados sensíveis a atacantes.

## Seção 3: Web Cache Poisoning: Transformando um Recurso de Desempenho em um Vetor de Ataque

### 3.1. Compreendendo o Cache da Web: Chaves, Entradas Não Chaveadas e a Superfície de Ataque

O **cache da web** armazena respostas HTTP para otimizar desempenho. A **Chave de Cache** (método, host, caminho da URL) determina se uma resposta é reutilizada. **Entradas Não Chaveadas** (cabeçalhos, cookies, parâmetros) podem influenciar a resposta sem afetar a chave, permitindo **Web Cache Poisoning (WCP)**.

### 3.2. Metodologias de Envenenamento

- **Cabeçalhos Não Chaveados**: Ex.: `X-Forwarded-Host: evil.com` pode injetar scripts maliciosos.
- **Parâmetros de Consulta Não Chaveados**: Ex.: `utm_content` refletido na resposta sem sanitização.
- **Cookies Não Chaveados**: Cookies que afetam a resposta, mas não a chave, podem carregar *payloads* XSS.
- **Requisições GET "Gordas"**: Corpos em GETs processados pelo back-end, mas ignorados pelo cache.

### 3.3. Encadeamento para Impacto Crítico

O WCP amplifica vulnerabilidades como XSS refletido ou *self-XSS* em XSS armazenado, afetando todos os visitantes de uma página. Também pode facilitar **DOM-XSS** ao envenenar recursos dinâmicos (ex.: JSON).

### 3.4. Cache Defensivo

- **Cabeçalho Vary**: Inclui cabeçalhos como `X-Forwarded-Host` na chave de cache.
- **Políticas Estratégicas**:
  - Armazenar apenas conteúdo estático.
  - Não confiar em entradas não chaveadas.
  - Desativar cache para conteúdo dinâmico (`Cache-Control: no-store`).

## Seção 4: DOM Clobbering: Manipulando a Lógica do Lado do Cliente Sem Scripts

### 4.1. O Comportamento Legado

O **DOM Clobbering** explora como elementos HTML com `id` ou `name` criam variáveis globais no `window` ou `document`. Exemplo:

```html
<a id="minhaVariavel"></a>
```

Cria `window.minhaVariavel`, sobrescrevendo variáveis JavaScript.

### 4.2. Clobbering Avançado

- **Elementos <form>**: Permitem acesso a filhos via `name`. Ex.:

```html
<form id="config">
  <input name="url" value="https://malicioso.com">
</form>
```

Cria `window.config.url`.

- **HTMLCollection**: Múltiplos elementos com o mesmo `id` formam uma coleção acessível por `name`. Ex.:

```html
<a id="config"></a>
<a id="config" name="url" href="https://malicioso.com/script.js"></a>
```

Cria `window.config.url`.

### 4.3. Do Clobbering ao Comprometimento

- **Habilitação de XSS**: Sobrescreve variáveis para carregar scripts maliciosos. Exemplo:

```javascript
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'};
```

**Payload**:

```html
<a id="defaultAvatar"></a>
<img id="defaultAvatar" name="avatar" src="cid:\"onerror=alert(1)//">
```

- **Bypass de CSRF**: Sobrescreve tokens CSRF em SPAs, anulando proteções.

### 4.4. Estratégias de Mitigação

- **Sanitização de HTML**: Usar DOMPurify com `SANITIZE_NAMED_PROPS: true`.
- **Object.freeze()**: Tornar objetos globais imutáveis, mas não protege APIs nativas.
- **CSP**: Impede scripts maliciosos, mas não ataques com código existente.
- **Codificação Segura**: Evitar variáveis globais não inicializadas; usar `let`/`const`.

## Seção 5: Mitigação Abrangente e Melhores Práticas

### 5.1. Uma Estratégia de Defesa em Múltiplas Camadas

| Vulnerabilidade         | Defesa Primária                     | Prática Chave                                  | Defesa Secundária                     |
|-------------------------|-------------------------------------|------------------------------------------------|---------------------------------------|
| Path Traversal          | Validação de Entrada (Allowlist)    | Validar caminhos contra lista de permissões    | Menores privilégios; *chrooted jails* |
| HTTP Request Smuggling  | HTTP/2 End-to-End                  | Desativar downgrade para HTTP/1.1              | Normalizar requisições; rejeitar ambiguidade |
| Web Cache Poisoning     | Configuração de Chave de Cache      | Incluir todas as entradas na chave (`Vary`)    | Cache apenas conteúdo estático        |
| DOM Clobbering          | Sanitização de HTML                | Usar DOMPurify com `SANITIZE_NAMED_PROPS`      | `Object.freeze()`; CSP estrita        |

### 5.2. Codificação Segura, Endurecimento de Configuração e Escolhas Arquitetônicas

- **Desenvolvedores**: Validar entradas com *allowlist*; evitar variáveis globais não inicializadas.
- **Administradores**: Harmonizar servidores para evitar dessincronização; configurar chaves de cache rigorosas.
- **Arquitetos**: Usar pilha homogênea; evitar downgrade de HTTP/2 para HTTP/1.1.

### 5.3. O Papel dos Protocolos e Frameworks Modernos

- **HTTP/2 e HTTP/3**: Eliminam HRS clássico com *framing* binário.
- **Frameworks JavaScript**: React escapa dados por padrão, mas evitar `dangerouslySetInnerHTML`.