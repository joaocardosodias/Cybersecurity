# Análise Aprofundada da Vulnerabilidade de *Prototype Pollution* em JavaScript

## 1. Introdução à Poluição de Protótipos

### Definição e Contexto

A *Prototype Pollution* (Poluição de Protótipos) é uma vulnerabilidade de segurança específica da linguagem JavaScript, que emerge diretamente de sua natureza de herança baseada em protótipos. Classificada como um ataque de injeção sem código (*code-less injection attack*), esta técnica permite que um atacante modifique o `Object.prototype`, o protótipo ancestral de quase todos os objetos em JavaScript. Ao injetar ou modificar propriedades no `Object.prototype`, o atacante não insere *scripts* maliciosos diretamente; em vez disso, ele altera o comportamento fundamental de objetos em toda a aplicação. Essa alteração pode subverter a lógica de segurança, levando a uma variedade de impactos adversos.

A relevância desta vulnerabilidade é acentuada no ecossistema de desenvolvimento moderno, que depende fortemente de JavaScript. Ela afeta não apenas aplicações do lado do cliente, como *Single-Page Applications* (SPAs), mas também, e de forma mais crítica, aplicações de back-end construídas em Node.js. No ambiente do servidor, onde o escopo de um processo é compartilhado entre múltiplas requisições, a poluição do protótipo global pode ter consequências devastadoras e persistentes. O impacto potencial de um ataque bem-sucedido varia significativamente, abrangendo desde a negação de serviço (*Denial of Service* - DoS) e o contorno de lógicas de autorização, até vulnerabilidades mais severas como *Cross-Site Scripting* (XSS) no lado do cliente e Execução Remota de Código (*Remote Code Execution* - RCE) no lado do servidor.

A exploração da *Prototype Pollution* é uma manifestação de um padrão recorrente em segurança de aplicações: a manipulação de comportamentos implícitos e "mágicos" de uma linguagem ou *framework*. Em linguagens como PHP, por exemplo, ataques de desserialização frequentemente visam os "*magic methods*" (`__wakeup()`, `__destruct()`), que são executados automaticamente pelo interpretador durante o ciclo de vida de um objeto, sem uma chamada explícita no código da aplicação. De forma análoga, a herança prototípica em JavaScript é um mecanismo automático. Quando uma propriedade não é encontrada em um objeto, o motor JavaScript percorre recursivamente a cadeia de protótipos (através da propriedade interna `[[Prototype]]`) para localizá-la. A vulnerabilidade de *Prototype Pollution* não explora uma falha em uma função específica, mas sim essa mecânica fundamental da linguagem. Isso implica que os desenvolvedores devem manter um ceticismo saudável em relação a qualquer recurso de linguagem que opere de forma implícita, pois é nesses pontos que as suposições de segurança frequentemente falham.

## 2. Fundamentos Essenciais: A Herança Prototípica em JavaScript

Para compreender a *Prototype Pollution*, é indispensável um entendimento sólido do modelo de herança do JavaScript. Diferente da herança baseada em classes, o JavaScript utiliza um modelo de herança prototípica, onde objetos herdam propriedades e métodos de outros objetos.

### O `Object.prototype`

No topo da cadeia de protótipos da maioria dos objetos JavaScript está o `Object.prototype`. Este objeto serve como o "ancestral" comum do qual quase todos os outros objetos herdam. Um objeto literal simples, como `let obj = {};`, não começa vazio; ele já possui acesso a métodos como `toString()`, `hasOwnProperty()`, e `valueOf()`, pois estes estão definidos no `Object.prototype`. Consequentemente, modificar este protótipo global significa que as modificações serão refletidas em praticamente todos os objetos criados na aplicação, a menos que tenham sido explicitamente criados sem um protótipo (usando `Object.create(null)`).

### A Cadeia de Protótipos

A conexão entre um objeto e seu protótipo é mantida através de uma propriedade interna, formalmente especificada como `[[Prototype]]`. Historicamente, essa propriedade era exposta através do acessor não padrão `__proto__`. Embora o uso de `__proto__` seja desaconselhado em favor de métodos modernos como `Object.getPrototypeOf()` e `Object.setPrototypeOf()`, sua presença e manipulabilidade são o epicentro técnico do ataque de *Prototype Pollution*. Essa situação é análoga a outras vulnerabilidades que surgem de funcionalidades legadas e mal compreendidas, como o DOM Clobbering, onde atalhos antigos do DOM criam vetores de ataque modernos.

Outro caminho para acessar o protótipo de um objeto é através da propriedade `constructor`. A expressão `obj.constructor.prototype` resolve para o protótipo do qual `obj` foi instanciado, fornecendo um vetor alternativo para o ataque.

A vulnerabilidade explora uma colisão de *namespace* fundamental. No DOM Clobbering, a colisão ocorre quando um elemento HTML, como `<form id="config">`, cria uma variável global `window.config`, fazendo com que o *namespace* do DOM "vaze" para o *namespace* global do JavaScript. Na *Prototype Pollution*, a colisão é entre as propriedades de um objeto de dados e as propriedades do próprio mecanismo de herança da linguagem. Quando um código vulnerável processa um objeto JSON como `{"__proto__": {"polluted": true}}`, ele trata `__proto__` como uma chave de dados comum. No entanto, o motor JavaScript interpreta essa chave como uma instrução para modificar a cadeia de protótipos. A validação de entrada, portanto, não deve se concentrar apenas no conteúdo dos valores, como é comum em defesas contra XSS, mas também na semântica das chaves em linguagens dinâmicas. Chaves como `__proto__` e `constructor` são, na prática, palavras-chave com significado especial que devem ser tratadas com extremo cuidado.

## 3. A Anatomia de um Ataque de *Prototype Pollution*

Um ataque de *Prototype Pollution* pode ser decomposto em três estágios lógicos: a fonte (onde a entrada maliciosa é injetada), o *payload* (os dados que poluem o protótipo) e o *gadget* (o código da aplicação que é subsequentemente explorado).

### A Fonte (O Ponto de Injeção)

A fonte da vulnerabilidade é tipicamente uma função que modifica um objeto JavaScript com base em uma entrada controlada pelo usuário, sem validar adequadamente as chaves dessa entrada. O padrão de código mais comum e vulnerável é a fusão recursiva de objetos (*deep merge* ou *extend*).

Considere a seguinte implementação ingênua de uma função de *merge*:

```javascript
function merge(target, source) {
  for (let key in source) {
    if (typeof target[key] === 'object' && target[key] !== null) {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

Se um atacante fornecer um objeto `source` derivado de um JSON malicioso como `JSON.parse('{"__proto__": {"isAdmin": true}}')`, o ataque se desenrola da seguinte forma:

1. O laço `for...in` itera sobre as chaves do objeto `source`. A única chave é `__proto__`.
2. A condição `if` falha, pois `target['__proto__']` não é um objeto (é o protótipo).
3. A execução prossegue para o `else`, resultando na atribuição `target['__proto__'] = source['__proto__']`.
4. Esta operação, em vez de criar uma propriedade chamada `__proto__` no objeto `target`, modifica o protótipo do objeto `target`. Se `target` for um objeto literal (`{}`), seu protótipo é `Object.prototype`.
5. Como resultado, `Object.prototype` agora contém a propriedade `{isAdmin: true}`.

Outras fontes comuns incluem funções de clonagem de objetos e o processamento de parâmetros de consulta de URL (*query strings*) que são convertidos em objetos aninhados e depois mesclados com objetos de configuração.

### O *Payload* Malicioso

O *payload* é o objeto JSON que contém as propriedades a serem injetadas no protótipo. Sua estrutura é projetada para atingir um objetivo específico:

- **Bypass de Autorização**: `{"__proto__": {"isAdmin": true}}`
- **Negação de Serviço**: `{"__proto__": {"toString": "CRASH"}}`
- **Vetor Alternativo**: `{"constructor": {"prototype": {"isAdmin": true}}}`

### O *Gadget* (O Ponto de Execução)

Após a poluição do protótipo, o atacante precisa de um "*gadget*": um trecho de código existente e, em si, benigno na aplicação, que agora se comporta de maneira maliciosa devido à propriedade injetada. Este conceito é central em várias classes de vulnerabilidades avançadas. Em ataques de desserialização, "*gadget chains*" são sequências de métodos em bibliotecas existentes que, quando invocados na ordem correta durante a desserialização, levam à execução de código. Similarmente, no DOM Clobbering, o código da aplicação que confia em uma variável global se torna um *gadget* quando essa variável é sobrescrita por um elemento DOM.

No contexto da *Prototype Pollution*, um *gadget* é qualquer parte do código que acessa uma propriedade de um objeto sem primeiro verificar se essa propriedade pertence ao próprio objeto.

**Exemplo de *Gadget*:**

Suponha que, em algum lugar da aplicação, exista o seguinte código para verificar permissões:

```javascript
function checkPermissions(user) {
  if (user.isAdmin) {
    console.log("Acesso de administrador concedido.");
    // Realiza ação privilegiada
  } else {
    console.log("Acesso negado.");
  }
}

let someUser = {}; // Um objeto de usuário normal, sem propriedade 'isAdmin'
checkPermissions(someUser);
```

Em uma execução normal, `someUser.isAdmin` é `undefined`, e o acesso é negado. No entanto, após o protótipo ter sido poluído com `{isAdmin: true}`, a verificação `if (user.isAdmin)` se torna verdadeira. O motor JavaScript não encontra `isAdmin` no objeto `someUser`, então ele sobe na cadeia de protótipos e encontra `isAdmin: true` no `Object.prototype`, concedendo acesso indevido.

A estrutura do ataque (Fonte -> *Gadget* -> *Sink*) representa um padrão universal em ataques de injeção de lógica. O fluxo de dados não confiáveis (a fonte) corrompe o estado do ambiente (a poluição do protótipo), o que faz com que um código legítimo (o *gadget*) se comporte de forma inesperada, levando a um resultado inseguro (o *sink*, como um *bypass* de segurança ou XSS). A mitigação, portanto, não deve focar apenas em "*sinks*" perigosos (como `eval`), mas deve começar na "fonte", tratando qualquer dado que possa influenciar a estrutura de objetos ou o ambiente de execução como fundamentalmente não confiável.

## 4. Cenários de Exploração e Impacto Real

A flexibilidade do JavaScript e a onipresença de `Object.prototype` abrem uma vasta gama de cenários de exploração. O impacto de um ataque de *Prototype Pollution* depende inteiramente dos *gadgets* disponíveis no código da aplicação alvo.

**Tabela: Relação entre Vetores de Injeção, *Gadgets* e Impactos**

| Vetor de Injeção Comum (Fonte) | Exemplo de *Gadget* de *Script* (Código Vulnerável) | Impacto Potencial | Exemplo de *Payload* |
|--------------------------------|----------------------------------------------------|-------------------|----------------------|
| Função de *merge* recursivo | `if (options.isAdmin) {... }` | *Bypass* de Autorização | `{"__proto__": {"isAdmin": true}}` |
| Processamento de *querystring* | `element.innerHTML = config.template;` | XSS do Lado do Cliente | `?__proto__[template]=<img src=x onerror=alert(1)>` |
| Clonagem de objeto | `child_process.exec(cmd, options)` | RCE no Lado do Servidor (Node.js) | `{"__proto__": {"shell": "/bin/bash",...}}` |
| Atribuição de propriedade aninhada | `if (obj.toString()) {... }` | Negação de Serviço (DoS) | `{"__proto__": {"toString": "crash"}}` |

### Análise Detalhada dos Cenários

#### Negação de Serviço (DoS)

Este é frequentemente o impacto mais fácil de alcançar. Ao poluir métodos essenciais como `Object.prototype.toString` ou `Object.prototype.hasOwnProperty` com um valor que não é uma função (por exemplo, uma *string* ou um booleano), um atacante pode causar exceções `TypeError` em todo o código que depende desses métodos. Muitos laços `for...in`, bibliotecas de *logging* e *frameworks* de serialização dependem implicitamente dessas funções, e sua sobrescrita pode paralisar o processo do Node.js ou o navegador do cliente.

#### *Bypass* de Controles de Segurança

Este é o cenário mais direto. O código da aplicação frequentemente verifica a existência de propriedades em objetos de configuração ou de usuário para tomar decisões de segurança. Por exemplo, `if (config.isSecure)` ou `if (user.roles.includes('admin'))`. Se um atacante poluir o protótipo com `isSecure: false` ou `roles: ['admin']`, ele pode subverter essa lógica sem modificar diretamente o objeto em questão.

#### *Cross-Site Scripting* (XSS)

A *Prototype Pollution* pode servir como um mecanismo de entrega para XSS, de forma análoga a como o *Web Cache Poisoning* pode transformar um XSS refletido em um XSS armazenado. O ataque ocorre quando um *gadget* de *script* usa uma propriedade de um objeto para renderizar conteúdo no DOM sem o devido saneamento. Por exemplo, se um *framework* de *templates* renderiza `<div>{{ config.htmlTemplate }}</div>` e um atacante polui o protótipo com `htmlTemplate: "<img src=x onerror=alert(1)>"`, qualquer objeto `config` que não tenha sua própria propriedade `htmlTemplate` herdará o *payload* malicioso, resultando em XSS.

#### Execução Remota de Código (RCE) em Node.js

Este é, de longe, o cenário de maior impacto. Muitas funções nativas e de bibliotecas populares em Node.js, como `child_process.exec()`, `fs.readFile()`, e *frameworks* web como Express, aceitam um objeto de *options* como parâmetro. Essas opções controlam como a função se comporta. Por exemplo, a função `child_process.exec()` pode aceitar uma opção `shell` para especificar qual *shell* usar para executar um comando. Se um atacante poluir o `Object.prototype` com `{"shell": "sh", "env": {"ATTACKER_VAR": "..."}}`, qualquer chamada a `exec()` na aplicação que não especifique explicitamente essas opções herdará as maliciosas do protótipo, potencialmente levando à execução de comandos arbitrários no servidor.

## 5. Estratégias Abrangentes de Mitigação e Prevenção

A mitigação da *Prototype Pollution* requer uma abordagem multifacetada, combinando validação de entrada, práticas de codificação segura e defesas em nível de ambiente.

### Validação e Saneamento de Entradas (Defesa na Fonte)

A defesa mais direta é impedir que chaves maliciosas entrem em funções de manipulação de objetos. Funções de *merge* ou *clone* devem ser reescritas para bloquear explicitamente chaves perigosas.

**Exemplo de Função de *merge* Segura:**

```javascript
function secureMerge(target, source) {
  for (let key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue; // Pula chaves perigosas
    }
    if (typeof target[key] === 'object' && target[key] !== null) {
      secureMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

Esta validação deve ser aplicada em todos os pontos de entrada onde dados estruturados (como JSON de corpos de requisição ou parâmetros de URL) são processados e usados para modificar objetos internos.

### Práticas de Codificação Segura

A melhor defesa é arquitetar o código de forma a evitar a classe do problema.

- **`Object.create(null)`**: Para criar objetos que funcionam como dicionários ou mapas de chave-valor, `Object.create(null)` é a abordagem preferível. Ele cria um objeto "puro" que não herda de `Object.prototype`. Como tal, ele não possui métodos como `toString()` e, mais importante, não é suscetível à poluição do protótipo global.
- **`Map`**: A estrutura de dados `Map`, introduzida no ES6, é uma alternativa moderna e segura para usar objetos como dicionários. As chaves em um `Map` não colidem com propriedades do protótipo, e ele foi projetado especificamente para armazenamento de chave-valor, oferecendo uma API mais limpa e segura.

### Mitigações a Nível de Ambiente

- **`Object.freeze(Object.prototype)`**: Esta é a defesa mais robusta, pois torna o `Object.prototype` imutável, impedindo qualquer tentativa de poluição. A técnica de congelar objetos é também sugerida como uma mitigação para DOM Clobbering. No entanto, esta abordagem tem uma desvantagem significativa: pode quebrar a funcionalidade de bibliotecas de terceiros que dependem da modificação de protótipos (uma prática geralmente desaconselhada, mas ainda existente). A implementação desta defesa requer testes de regressão extensivos para garantir a compatibilidade com todas as dependências do projeto.

A escolha pela mitigação mais eficaz reflete uma maturidade na abordagem de segurança. Enquanto a validação de entrada é uma medida reativa e `Object.freeze` é uma medida de força bruta, a adoção de `Object.create(null)` ou `Map` é uma escolha de design proativa. Isso demonstra que a prevenção de vulnerabilidades complexas está mais profundamente ligada à arquitetura de software e às práticas de codificação idiomáticas do que a remendos de segurança aplicados posteriormente.

### Detecção com Ferramentas de Segurança

- **SAST (*Static Application Security Testing*)**: Ferramentas SAST podem ser configuradas para analisar o código-fonte em busca de padrões de código vulneráveis, como funções de *merge* recursivas que não validam a chave `__proto__`, ou o acesso a propriedades de objetos sem a verificação `hasOwnProperty`. Esta abordagem é eficaz para encontrar vulnerabilidades conhecidas em código proprietário.
- **DAST (*Dynamic Application Security Testing*)**: Ferramentas DAST podem ser usadas para testar ativamente uma aplicação em execução. Elas podem injetar *payloads* de poluição de protótipos conhecidos em parâmetros de entrada (corpos de requisição, URLs) e monitorar a aplicação em busca de comportamentos anômalos, como *crashes* (DoS), respostas inesperadas (*bypass* de lógica) ou interações com sistemas externos (indicando XSS ou RCE).

## 6. Conclusão

A *Prototype Pollution* é uma vulnerabilidade sutil, mas poderosa, que explora a mecânica central do modelo de herança do JavaScript. Sua capacidade de modificar silenciosamente o comportamento de objetos globais a torna uma ameaça significativa, com um espectro de impacto que vai desde a interrupção do serviço até a completa tomada de controle do servidor.

A análise aprofundada revela que, embora existam mitigações reativas, como o saneamento de entradas e o congelamento de protótipos, as defesas mais robustas e sustentáveis são arquiteturais. A adoção de práticas de codificação seguras, como o uso de `Object.create(null)` para dicionários e a preferência pela estrutura de dados `Map`, elimina a classe de vulnerabilidade por design.

Em última análise, a defesa contra a *Prototype Pollution* e outras vulnerabilidades avançadas de injeção de lógica não reside apenas na aplicação de *patches* ou na configuração de ferramentas, but em uma compreensão profunda dos fundamentos da linguagem de programação. É o conhecimento íntimo de como o JavaScript lida com objetos e protótipos que permite aos desenvolvedores escrever código que não apenas funciona como esperado, mas que também é inerentemente resistente a manipulações sutis que podem levar a falhas de segurança catastróficas.