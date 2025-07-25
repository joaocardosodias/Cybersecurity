# Relatório de Análise de Vulnerabilidade: Poluição de Parâmetros HTTP (HPP)

## Introdução à Poluição de Parâmetros HTTP (HPP): Uma Análise de um Vetor de Ataque Sutil

### Definindo HPP: Além da Simples Entrada de Dados, Explorando a Ambiguidade nos Padrões Web

A Poluição de Parâmetros HTTP (HTTP Parameter Pollution - HPP) é uma técnica de evasão de ataques que explora a ambiguidade na forma como as aplicações web processam requisições HTTP que contêm múltiplas instâncias de um parâmetro com o mesmo nome. Fundamentalmente, o HPP é uma vulnerabilidade de validação de entrada que permite a um atacante injetar delimitadores de string de consulta codificados para manipular ou recuperar informações ocultas. Esta técnica não se limita a uma única falha de implementação; em vez disso, ela surge de uma inconsistência fundamental no ecossistema da web, onde diferentes tecnologias de servidor e frameworks interpretam a mesma requisição de maneiras drasticamente diferentes.

Ao contrário de vulnerabilidades mais diretas, como a Injeção de SQL (SQLi) ou o Cross-Site Scripting (XSS), o HPP raramente é uma vulnerabilidade de alto impacto por si só. Seu verdadeiro perigo reside em sua capacidade de atuar como um facilitador, permitindo que um atacante contorne mecanismos de segurança, como Web Application Firewalls (WAFs), e execute ataques mais severos. Ao dividir um vetor de ataque em múltiplos parâmetros, um atacante pode ofuscar a carga maliciosa, tornando-a invisível para filtros de segurança que inspecionam cada parâmetro isoladamente. O servidor, ao processar esses parâmetros fragmentados, pode inadvertidamente reagrupar a carga maliciosa, permitindo que o ataque prossiga sem ser detectado.

## A Causa Raiz: Análise do Tratamento Inconsistente de Parâmetros no Stack Web

A existência da Poluição de Parâmetros HTTP é um sintoma direto da ausência de um padrão formal e universalmente adotado que dite como os servidores web devem lidar com parâmetros duplicados numa requisição HTTP. Os documentos RFC relevantes permitem a submissão de múltiplos parâmetros com o mesmo nome, mas não especificam um método de tratamento obrigatório. Esta omissão forçou cada desenvolvedor de tecnologia web — desde servidores como Apache e IIS até frameworks como ASP.NET, PHP, Django e Express.js — a implementar sua própria lógica de análise. O resultado é um mosaico de comportamentos inconsistentes que formam a base para a exploração do HPP.

Essa inconsistência cria o que é conhecido como uma "incompatibilidade de impedância" (impedance mismatch) ou uma dessincronização entre diferentes componentes de uma arquitetura de aplicação moderna. Em um ambiente de produção típico, uma requisição HTTP pode passar por múltiplas camadas antes de chegar à lógica de negócios: um CDN, um WAF na nuvem, um balanceador de carga, um proxy reverso e, finalmente, o servidor da aplicação. Cada uma dessas camadas pode analisar a requisição de forma independente. Um atacante explora essa dessincronização ao criar uma requisição que parece benigna para a camada de segurança externa (por exemplo, um WAF que lê apenas a primeira instância de um parâmetro), mas que revela sua natureza maliciosa para a aplicação backend (que pode, por exemplo, ler a última instância ou concatenar todas as instâncias). Portanto, o HPP não é apenas uma falha em um único software, mas uma vulnerabilidade sistêmica que emerge da complexidade e heterogeneidade das arquiteturas web modernas. Quanto mais camadas de análise uma requisição atravessa, maior se torna a superfície de ataque para o HPP.

## Distinguindo HPP: Vulnerabilidades do Lado do Servidor vs. Lado do Cliente

As vulnerabilidades de HPP manifestam-se em dois domínios distintos, cada um com seus próprios vetores de ataque e impactos potenciais.

### HPP do Lado do Servidor (Server-Side HPP)

Nesta variante, o ataque visa o ambiente de backend da aplicação. O objetivo do atacante é manipular a forma como o servidor processa os parâmetros para alterar a lógica da aplicação, contornar controles de acesso, acessar dados não autorizados ou interagir com outros sistemas de backend. Os ataques de HPP do lado do servidor são frequentemente os mais perigosos, pois podem ser encadeados com outras vulnerabilidades para alcançar a execução remota de código (RCE) ou a exfiltração de dados sensíveis da base de dados.

### HPP do Lado do Cliente (Client-Side HPP)

No HPP do lado do cliente, o alvo é o navegador do usuário vítima. O atacante explora a forma como o código do lado do cliente (geralmente JavaScript) processa parâmetros da URL para manipular dinamicamente o conteúdo da página. Ao poluir os parâmetros que são lidos por scripts do lado do cliente, um atacante pode modificar links, ações de formulários e fontes de recursos (src, href), levando a ataques de phishing, redirecionamentos abertos ou até mesmo XSS.

## A Mecânica do HPP: Como as Tecnologias Web Interpretam Requisições Ambíguas

### Análise Comparativa do Tratamento de Parâmetros

A exploração bem-sucedida do HPP depende de um conhecimento profundo sobre como a tecnologia alvo interpreta múltiplos parâmetros com o mesmo nome. O comportamento varia significativamente entre diferentes servidores e frameworks, e essa divergência é a chave para criar cargas úteis eficazes. A tabela abaixo, compilada a partir de pesquisas da OWASP, ilustra essa diversidade de comportamentos para uma URL de exemplo: `https://example.com/?color=red&color=blue`.

| **Tecnologia / Framework**           | **Comportamento de Análise**                            | **Resultado para ?color=red&color=blue** |
|--------------------------------------|--------------------------------------------------------|------------------------------------------|
| ASP.NET / IIS                        | Concatena todas as ocorrências com uma vírgula          | color=red,blue                          |
| ASP / IIS                            | Concatena todas as ocorrências com uma vírgula          | color=red,blue                          |
| .NET Core 3.1 / Kestrel              | Concatena todas as ocorrências com uma vírgula          | color=red,blue                          |
| .NET 5 / Kestrel                     | Concatena todas as ocorrências com uma vírgula          | color=red,blue                          |
| PHP / Apache                         | Utiliza apenas a última ocorrência                     | color=blue                              |
| PHP / Zeus                           | Utiliza apenas a última ocorrência                     | color=blue                              |
| JSP, Servlet / Apache Tomcat          | Utiliza apenas a primeira ocorrência                   | color=red                               |
| JSP, Servlet / Oracle App Server      | Utiliza apenas a primeira ocorrência                   | color=red                               |
| JSP, Servlet / Jetty                 | Utiliza apenas a primeira ocorrência                   | color=red                               |
| IBM Lotus Domino                     | Utiliza apenas a última ocorrência                     | color=blue                              |
| IBM HTTP Server                      | Utiliza apenas a primeira ocorrência                   | color=red                               |
| Node.js / Express                    | Agrupa as ocorrências em um array                      | color=['red','blue'] (em req.query)     |
| Python / Zope                        | Agrupa as ocorrências em uma lista                     | color=['red','blue']                    |
| mod_perl, libapreq2 / Apache         | Utiliza apenas a primeira ocorrência                   | color=red                               |
| Perl CGI / Apache                    | Utiliza apenas a primeira ocorrência                   | color=red                               |
| mod_wsgi (Python) / Apache           | Utiliza apenas a primeira ocorrência                   | color=red                               |

Esta tabela serve como uma referência fundamental tanto para atacantes quanto para defensores. Para um pentester, ela fornece o conhecimento necessário para criar ataques direcionados. Por exemplo, para atacar uma aplicação PHP, um atacante colocaria o valor benigno no primeiro parâmetro e o valor malicioso no último. Para uma aplicação baseada em Tomcat, a ordem seria invertida. Para um desenvolvedor, esta tabela destaca o comportamento inerente do seu stack tecnológico, informando sobre os riscos que precisam ser mitigados no código.

### Aprofundamento em Frameworks Específicos

Para além do comportamento geral, é crucial entender como os desenvolvedores interagem com esses parâmetros no código, pois é aí que as vulnerabilidades são introduzidas.

#### ASP.NET /.NET Core

Em ambientes ASP.NET, os parâmetros duplicados são concatenados numa única string separada por vírgulas. Um desenvolvedor que acesse `Request.QueryString["color"]` receberá a string `"red,blue"`. Se a aplicação não estiver preparada para analisar esta string (por exemplo, esperando um único valor inteiro), isso pode levar a erros de conversão de tipo ou a comportamentos inesperados. Embora o ASP.NET Core ofereça mecanismos mais robustos, como a vinculação de modelos (model binding) que pode mapear múltiplos valores para um array, uma implementação ingênua que ainda trata o parâmetro como uma string simples permanece vulnerável.

#### PHP / Apache

O comportamento padrão do PHP é usar o valor do último parâmetro. Quando um desenvolvedor acessa `$_GET['color']`, o valor retornado será `'blue'`. Este comportamento "último ganha" é um dos mais explorados em ataques de HPP, pois permite que um atacante anexe um parâmetro malicioso no final de uma string de consulta, substituindo um valor potencialmente hardcoded ou benigno que veio antes.

#### Java Servlets (Tomcat, Jetty)

As implementações de Java Servlet, como as encontradas no Tomcat e Jetty, adotam uma abordagem de "primeiro ganha". A chamada a `request.getParameter("color")` retornará `'red'`. No entanto, a API de Servlet fornece um método para acessar todos os valores: `request.getParameterValues("color")`, que retornaria um array de strings `{"red", "blue"}`. Uma vulnerabilidade surge quando um desenvolvedor, desconhecendo a possibilidade de HPP, usa `getParameter()` assumindo que apenas um valor é possível, ignorando assim os parâmetros subsequentes que poderiam conter dados maliciosos. A complexidade aumenta em cenários de encaminhamento de requisições (`RequestDispatcher.forward()`), onde os parâmetros da requisição original e do caminho de encaminhamento podem ser agregados, levando a resultados inesperados.

#### Python (Django & Flask)

Frameworks Python oferecem um controle mais explícito sobre o acesso a parâmetros múltiplos, mas a segurança ainda depende do conhecimento do desenvolvedor.

- **Django**: O acesso a `request.GET.get('color')` ou `request.GET['color']` retorna o último valor (`'blue'`), semelhante ao PHP. Para acessar todos os valores, o desenvolvedor deve usar explicitamente `request.GET.getlist('color')`, que retorna `['red', 'blue']`. A falha comum é o uso de `.get()` quando múltiplos valores podem ser fornecidos, levando a uma substituição de parâmetro não intencional.
- **Flask**: De forma diferente, `request.args.get('color')` retorna o primeiro valor (`'red'`). Assim como em Django, para acessar todos os valores, é necessário usar `request.args.getlist('color')`. Esta inconsistência entre frameworks populares em Python destaca a necessidade de os desenvolvedores estarem cientes do comportamento específico da sua ferramenta.

#### Node.js (Express)

O Express.js se destaca por tratar parâmetros duplicados de forma inerentemente plural. Quando uma requisição como `?color=red&color=blue` é recebida, `req.query.color` é automaticamente populado como um array: `['red', 'blue']`. Este comportamento é mais seguro por padrão, pois não descarta silenciosamente nenhum dado. No entanto, uma vulnerabilidade pode surgir se o desenvolvedor esperar uma string e não validar que `req.query.color` é, na verdade, um array. Por exemplo, `if (req.query.color === 'red')` falharia, mas um código que processa o valor sem verificar seu tipo poderia ser explorado.

## Exploração de HPP do Lado do Servidor: Cenários de Ataque Avançados

### Bypass de Web Application Firewalls (WAFs) para Ataques de Injeção (SQLi)

Um dos casos de uso mais críticos para o HPP do lado do servidor é o bypass de WAFs para facilitar ataques de injeção, como SQL Injection (SQLi). Este ataque explora a dessincronização entre como o WAF e a aplicação backend analisam a mesma requisição HTTP.

#### Cenário de Ataque Passo a Passo

**Contexto**: Considere uma aplicação web vulnerável a SQLi no parâmetro `id`. A aplicação está protegida por um WAF que bloqueia padrões de SQLi conhecidos (ex: `UNION SELECT`, `OR 1=1`). A aplicação backend é construída em ASP.NET sobre IIS, que, como vimos na Tabela 2.1, concatena valores de parâmetros duplicados usando uma vírgula.

**Tentativa de Ataque Padrão (Bloqueada)**: O atacante primeiro tenta uma injeção de SQL clássica para extrair dados:

```
https://example.com/products?id=1' UNION SELECT username, password FROM users--
```

O WAF inspeciona o parâmetro `id`, detecta a string maliciosa `' UNION SELECT '` e bloqueia a requisição imediatamente.

**Criação do Ataque com HPP (Bypass)**: Sabendo que o backend é ASP.NET, o atacante decide dividir a carga maliciosa em duas partes, usando duas instâncias do parâmetro `id`. A carga útil é dividida em um ponto sintaticamente inócuo, como dentro de um comentário SQL, para enganar o WAF.

```
https://example.com/products?id=1' UNION SELECT username/*&id=*/,password FROM users--
```

**Análise pelo WAF**: O WAF recebe a requisição e analisa os parâmetros separadamente:

- `id = 1' UNION SELECT username/*`
- `id = */,password FROM users--`

O WAF examina cada valor de forma isolada. Nenhum dos valores contém a assinatura completa e bloqueável `UNION SELECT`. A primeira parte termina com um comentário de bloco SQL aberto (`/*`), e a segunda começa com um comentário de bloco fechado (`*/`). Para um WAF baseado em assinaturas simples, ambos os fragmentos podem parecer benignos ou, no mínimo, incompletos, e a requisição é permitida a passar para o servidor da aplicação.

**Processamento no Backend (ASP.NET/IIS)**: O servidor ASP.NET recebe a requisição com os dois parâmetros `id`. De acordo com seu comportamento, ele concatena os valores, resultando na string:

```
"1' UNION SELECT username/*,*/,password FROM users--"
```

A string de consulta SQL final que é construída dinamicamente pela aplicação se torna:

```
SELECT * FROM products WHERE id = '1' UNION SELECT username/*,*/,password FROM users--'
```

O trecho `/*,*/` é tratado pelo motor SQL como um comentário vazio, e a vírgula original que separava os valores dos parâmetros é efetivamente ignorada. A carga útil maliciosa é perfeitamente remontada após ter passado pela inspeção do WAF.

**Resultado**: A consulta SQL maliciosa é executada com sucesso no banco de dados, e o atacante consegue extrair os nomes de usuário e senhas, contornando completamente o WAF. Este exemplo demonstra como o HPP transforma o WAF de uma defesa em um obstáculo contornável.

### Manipulação da Lógica de Negócios: O Caso de Transferências de Fundos Não Autorizadas

O HPP pode ser usado para explorar falhas na lógica de negócios de uma aplicação, muitas vezes em arquiteturas complexas como microserviços, onde diferentes componentes podem processar a mesma requisição de maneiras distintas.

#### Cenário de Ataque Passo a Passo

**Contexto**: Uma aplicação bancária permite transferências de fundos através de um endpoint `POST /api/transfer`. A arquitetura é baseada em microserviços. A requisição passa por dois serviços distintos:

- **Serviço de Validação**: Escrito em Java (usando Tomcat), ele verifica se o usuário autenticado tem permissão e fundos suficientes na conta de origem (`from_acct`). Este serviço lê a primeira ocorrência de um parâmetro.
- **Serviço de Transação**: Escrito em PHP (usando Apache), ele executa a transferência de fundos. Este serviço lê a última ocorrência de um parâmetro.

**Requisição Legítima**: Um usuário legítimo (`USER_B`) quer transferir $100 para outro usuário (`USER_C`). O corpo da requisição POST seria:

```
from_acct=USER_B&to_acct=USER_C&amount=100
```

**Criação do Ataque com HPP**: Um atacante (`ATTACKER`) quer transferir $5000 da conta de uma vítima (`VICTIM`) para a sua própria conta. O atacante está autenticado com a sua própria conta. Ele cria a seguinte requisição POST:

```
from_acct=ATTACKER&to_acct=ATTACKER_RECEIVER&amount=5000&from_acct=VICTIM
```

**Análise pelo Serviço de Validação (Lê o Primeiro)**: O Serviço de Validação em Java recebe a requisição. Ao processar o parâmetro `from_acct`, ele lê apenas a primeira ocorrência: `from_acct=ATTACKER`. O serviço então realiza as verificações de segurança:

- O usuário autenticado é `ATTACKER`? Sim.
- A conta de origem é `ATTACKER`? Sim.
- A conta `ATTACKER` tem fundos suficientes para transferir $5000? Sim.

A validação é bem-sucedida, e a requisição é encaminhada para o próximo serviço.

**Processamento no Serviço de Transação (Lê o Último)**: O Serviço de Transação em PHP recebe a mesma requisição. No entanto, ao processar o parâmetro `from_acct`, ele lê a última ocorrência: `from_acct=VICTIM`. O serviço então executa a lógica de transferência de fundos com os seguintes valores:

- Conta de origem: `VICTIM`
- Conta de destino: `ATTACKER_RECEIVER`
- Valor: $5000

**Resultado**: $5000 são transferidos da conta da vítima para a conta do atacante. A falha na lógica de negócios foi explorada com sucesso, não por uma injeção de código, mas pela exploração da inconsistência de análise de parâmetros entre dois componentes do backend. Este ataque é extremamente sutil, pois os logs do Serviço de Validação mostrariam uma transação aparentemente legítima da conta do próprio atacante, enquanto os logs do Serviço de Transação mostrariam a transação fraudulenta.

## Exploração de HPP do Lado do Cliente: Manipulando o Navegador do Usuário

### Criação de Redirecionamentos Abertos Maliciosos para Campanhas de Phishing

O HPP do lado do cliente ocorre quando um script no navegador da vítima interpreta parâmetros da URL de forma insegura. Este vetor pode ser usado para criar ataques de redirecionamento aberto, que são altamente eficazes em campanhas de phishing, pois a URL inicial pertence a um domínio confiável.

#### Cenário de Ataque Passo a Passo

**Contexto**: Um site confiável, `https://trustedsite.com`, possui uma funcionalidade de login que redireciona os usuários para uma página específica após a autenticação. A URL de redirecionamento é passada através de um parâmetro `redirectURL`. Exemplo de URL legítima:

```
https://trustedsite.com/login?redirectURL=/dashboard
```

Um script do lado do cliente na página de login lê este parâmetro para realizar o redirecionamento:

```javascript
// Código vulnerável no lado do cliente
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const redirect = urlParams.get('redirectURL');
if (redirect) {
  window.location.href = redirect;
}
```

**Mecanismo de Exploração**: O método `URLSearchParams.get()` em todos os navegadores modernos retorna o valor da primeira ocorrência de um parâmetro. A vulnerabilidade surge se o servidor que gera o link de login for suscetível a HPP e se o atacante puder injetar um segundo parâmetro `redirectURL`.

**Ataque com HPP**: O atacante descobre uma funcionalidade em `trustedsite.com` (por exemplo, um link "partilhar por email") onde pode influenciar os parâmetros adicionados a uma URL. Ele injeta um parâmetro `redirectURL` malicioso.

**URL Maliciosa Gerada**: O link final enviado à vítima numa campanha de phishing parece legítimo, mas está poluído:

```
https://trustedsite.com/login?redirectURL=https://evil-phishing-site.com&redirectURL=/dashboard
```

Neste caso, invertemos a ordem para explorar o comportamento "primeiro ganha" do script do lado do cliente.

**Execução no Navegador da Vítima**:

1. A vítima clica no link, confiando no domínio `trustedsite.com`.
2. A página de login carrega, e o script do lado do cliente é executado.
3. A linha `urlParams.get('redirectURL')` é executada. Como `get()` retorna a primeira ocorrência, o valor obtido é `https://evil-phishing-site.com`.
4. A linha `window.location.href = redirect;` redireciona o navegador da vítima para o site de phishing do atacante.

**Resultado**: A vítima é redirecionada para um site malicioso que pode imitar a página de login de `trustedsite.com` para roubar as suas credenciais. O HPP do lado do cliente foi usado para contornar a confiança do usuário no domínio inicial.

### Poluindo Scripts do Lado do Cliente e Links de Recursos (href, src)

O HPP também pode ser usado para manipular a forma como uma página carrega recursos dinâmicos, como scripts JavaScript ou folhas de estilo CSS, podendo levar a ataques de Path Traversal ou XSS.

#### Cenário de Ataque

**Contexto**: Uma página em `https://example.com` carrega módulos de JavaScript dinamicamente com base num parâmetro `module` na URL.

```
https://example.com/app?module=dashboard
```

O script na página constrói o caminho para o ficheiro `.js` da seguinte forma:

```javascript
// Script de carregamento de módulo no lado do cliente
const moduleName = new URLSearchParams(window.location.search).get('module');
const script = document.createElement('script');
script.src = '/js/modules/' + moduleName + '.js';
document.body.appendChild(script);
```

**Ataque com HPP**: O atacante cria uma URL que polui o parâmetro `module`, tentando explorar uma vulnerabilidade de Path Traversal.

```
https://example.com/app?module=../../../../malicious/payload&module=dashboard
```

Neste caso, a ordem dos parâmetros é crucial. O atacante coloca o payload malicioso primeiro, explorando o comportamento `get()` do `URLSearchParams`.

**Resultado**:

1. O script do lado do cliente executa `new URLSearchParams(window.location.search).get('module')`.
2. Este método retorna o valor da primeira ocorrência: `../../../../malicious/payload`.
3. O script então tenta carregar um ficheiro de `/js/modules/../../../../malicious/payload.js`.
4. Dependendo da configuração do servidor, esta Path Traversal pode ser bem-sucedida, permitindo ao atacante sair do diretório `/js/modules/` e carregar um script de um endpoint malicioso que ele possa ter conseguido alojar na aplicação (por exemplo, através de um upload de ficheiro). Se o script `payload.js` contiver código malicioso (por exemplo, `alert(document.cookie)`), o resultado é um ataque de XSS.

Este cenário demonstra um ataque em cadeia: o HPP é o vetor inicial que permite a exploração de uma vulnerabilidade de Path Traversal, que por sua vez resulta em XSS. A manipulação de recursos do lado do cliente é um vetor poderoso, pois o código malicioso é executado no contexto do domínio confiável.

## Uma Abordagem Metódica para Detecção e Mitigação

### Técnicas de Detecção Manual e Automatizada

A detecção de vulnerabilidades de HPP requer uma abordagem sistemática, pois o seu impacto depende do comportamento específico da aplicação.

#### Detecção Manual

A OWASP recomenda uma metodologia manual de três passos para cada parâmetro numa aplicação, que visa identificar a "incompatibilidade de impedância" entre diferentes componentes:

1. **Requisição Base**: Envie uma requisição normal com um único parâmetro e um valor válido. Registe a resposta do servidor.
   - Exemplo: `GET /page?param=value1`
2. **Requisição de Teste**: Substitua o valor do parâmetro por um valor de teste e envie a requisição. Registe a resposta.
   - Exemplo: `GET /page?param=HPP_TEST`
3. **Requisição Poluída**: Envie uma requisição que combine as duas anteriores, incluindo o parâmetro duas vezes com ambos os valores. Registe a resposta.
   - Exemplo: `GET /page?param=value1&param=HPP_TEST`
4. **Análise**: Compare as três respostas. Uma vulnerabilidade de HPP é provável se a resposta da Requisição Poluída (3) for diferente tanto da resposta Base (1) como da resposta de Teste (2). Esta diferença indica que a aplicação está a processar os parâmetros duplicados de uma forma não padrão (por exemplo, concatenando-os ou aplicando uma lógica diferente), o que pode ser explorável. Para o HPP do lado do cliente, o processo é semelhante, mas o atacante injeta um delimitador codificado (ex: `%26HPP_TEST`) e inspeciona o código-fonte da resposta HTML em busca de ocorrências descodificadas (`&HPP_TEST`) em atributos como `href`, `src` ou ações de formulários.

#### Detecção Automatizada

Embora a detecção manual seja crucial para entender a lógica de negócios, ferramentas automatizadas podem acelerar a descoberta de potenciais pontos de HPP.

- **Ferramentas de Fuzzing**: Ferramentas como o `HPPFuzZBu5t3R` são projetadas especificamente para testar vulnerabilidades de HPP, automatizando o processo de envio de múltiplos parâmetros com diferentes valores e analisando as respostas.
- **Proxies de Interceção**: Ferramentas como o Burp Suite, especialmente com extensões como o `Param Miner`, podem ser usadas para detetar parâmetros ocultos e testar como a aplicação lida com a duplicação de parâmetros conhecidos e desconhecidos.

### Programação Defensiva: Práticas de Codificação Segura para o Tratamento de Parâmetros

A mitigação mais eficaz para o HPP reside na implementação de práticas de codificação seguras e na validação rigorosa de todas as entradas do usuário.

- **Princípio Fundamental - Validação do Lado do Servidor**: Nunca confie em dados provenientes do cliente. Toda a validação de parâmetros deve ser realizada no lado do servidor. Qualquer parâmetro que não seja explicitamente esperado pela aplicação