# A Anatomia de uma Exploração de Confiança: Uma Análise Aprofundada do CSRF em Endpoints sem Verificação de Token

## Introdução à Falsificação de Requisição Entre Sites como um Ataque de "Deputado Confuso"

A Falsificação de Requisição Entre Sites, ou *Cross-Site Request Forgery* (CSRF), é uma exploração maliciosa na qual comandos não autorizados são submetidos a partir de um usuário em que uma aplicação web confia. Fundamentalmente, o CSRF representa uma instância do clássico "Problema do Deputado Confuso" (*Confused Deputy Problem*) na segurança da computação. Neste cenário, o navegador do usuário atua como o "deputado confuso", uma entidade com autoridade (a sessão autenticada do usuário) que é enganada por outra entidade com menos privilégios (um *site* malicioso) para usar indevidamente essa autoridade. Esta distinção é crucial: enquanto o *Cross-Site Scripting* (XSS) explora a confiança que um usuário deposita em um *site*, o CSRF explora a confiança que um *site* deposita no navegador de um usuário.

O mecanismo central que permite esta confusão é o comportamento padrão e automático dos navegadores de incluir credenciais, como *cookies* de sessão, em todas as requisições enviadas para um domínio específico, independentemente da origem da requisição. O ataque funciona porque a designação de uma ação (a requisição forjada) é passada do atacante para o navegador, mas a permissão para executar essa ação (o *cookie* de sessão) é fornecida de forma não intencional e automática pelo navegador, sem o consentimento explícito do usuário.

O processo pode ser decomposto da seguinte forma:

1. Um usuário se autentica em um *site* legítimo, como *banco.com*, e o navegador armazena um *cookie* de sessão que representa a autoridade do usuário.
2. Posteriormente, o usuário visita um *site* malicioso, *malicioso.com*, que não possui autoridade alguma com *banco.com*.
3. O *site* *malicioso.com* instrui o navegador do usuário a enviar uma requisição para uma ação de mudança de estado em *banco.com*, como *banco.com/transferir*. O navegador, agindo como o *deputado*, cumpre a instrução.
4. Crucialmente, o navegador anexa o *cookie* de sessão de *banco.com* a esta requisição. A autoridade é anexada implicitamente, sem ter sido fornecida explicitamente por *malicioso.com*.
5. O servidor de *banco.com* recebe a requisição, observa um *cookie* de sessão válido e assume que a requisição foi iniciada intencionalmente pelo usuário, executando assim a transferência. O servidor é "confundido" porque não consegue distinguir a requisição forjada de uma legítima, demonstrando o *problema do deputado confuso*, onde a permissão é aplicada de forma não intencional.

## A Mecânica da Confiança: Como a Submissão Automática de Cookies Habilita o CSRF

O vetor de ataque CSRF é intrinsecamente ligado ao modelo de gerenciamento de sessão da *web*, especificamente o manejo de *cookies*. Quando um usuário se autentica em uma aplicação, o servidor estabelece uma sessão e envia um identificador de sessão para o navegador, geralmente na forma de um *cookie*. Para cada requisição subsequente àquele domínio, o navegador anexa automaticamente o *cookie* de sessão correspondente.

Este mecanismo, projetado para conveniência e para manter o estado em um protocolo sem estado como o HTTP, torna-se a principal vulnerabilidade explorada pelo CSRF. O ataque é viável porque a aplicação do lado do servidor não consegue diferenciar entre uma requisição legitimamente iniciada pelo usuário dentro da aplicação e uma requisição forjada iniciada por um *site* de terceiros, mas executada pelo mesmo navegador autenticado. Para o servidor, ambas as requisições são idênticas: elas chegam do endereço IP do usuário e contêm o *cookie* de sessão correto.

## Os Três Pilares da Vulnerabilidade: Ação, Manejo de Sessão e Previsibilidade

Para que um ataque CSRF seja bem-sucedido, três condições essenciais devem ser atendidas simultaneamente. A ausência de qualquer uma delas torna a exploração inviável:

1. **Uma Ação Relevante**: A aplicação deve possuir uma funcionalidade que realize uma mudança de estado e que seja de interesse para um atacante. Exemplos incluem alterar a senha do usuário, transferir fundos, atualizar o endereço de e-mail ou modificar permissões. Requisições que apenas recuperam dados (idempotentes) geralmente não são alvos de CSRF, pois o atacante não pode ver a resposta. No entanto, aplicações que violam as melhores práticas e usam requisições GET para operações de mudança de estado são particularmente vulneráveis.
2. **Manejo de Sessão Baseado em Cookies**: A aplicação deve depender exclusivamente de *cookies* de sessão ou outros mecanismos de autenticação enviados automaticamente pelo navegador (como Autenticação Básica HTTP) para identificar o usuário. Se a aplicação utiliza um mecanismo adicional para validar requisições, como um *token* anti-CSRF, o ataque falhará.
3. **Parâmetros de Requisição Previsíveis**: O atacante deve ser capaz de determinar ou adivinhar todos os parâmetros necessários para construir uma requisição válida que execute a ação desejada. Por exemplo, uma função de alteração de senha não será vulnerável a CSRF se exigir que o usuário forneça a senha atual, um parâmetro que o atacante não tem como saber.

## Forjando Requisições: Vetores de Ataque em um Ambiente sem Tokens

### A Simplicidade dos Ataques Baseados em GET: Exploração via `<img>`, `<a>` e Outras *Tags* HTML

Ataques CSRF que exploram requisições GET são os mais simples de executar, pois podem ser acionados por diversas *tags* HTML padrão que fazem o navegador buscar um recurso externo. Uma das técnicas mais comuns e eficazes envolve o uso da *tag* `<img>`.

Um atacante pode incorporar uma *tag* `<img>` em uma página maliciosa, onde o atributo `src` aponta para a URL da ação vulnerável no *site* alvo. Quando o navegador da vítima tenta carregar a imagem, ele envia automaticamente uma requisição GET para a URL especificada, incluindo quaisquer *cookies* de sessão associados ao domínio alvo. Para tornar o ataque invisível, a imagem pode ser estilizada com dimensões de 0x0 pixels.

**Considere o seguinte cenário de ataque**:

```html
<p>Veja esta imagem engraçada!</p>
<img src="http://banco.com/transferir.do?destinatario=ATACANTE&valor=100000" width="0" height="0" border="0">
```

Neste exemplo, assim que a página do atacante é carregada, o navegador da vítima envia uma requisição GET para *banco.com* para realizar uma transferência. Como a vítima está autenticada, o *cookie* de sessão é enviado, e o banco, se vulnerável, processa a transação. Outras *tags*, como `<a>`, também podem ser usadas, embora geralmente exijam uma interação do usuário (um clique), que pode ser induzida por meio de engenharia social.

### A Ilusão de Segurança: Por Que Ataques Baseados em POST Permanecem Viáveis via Formulários de Auto-submissão

Uma concepção errônea comum é que restringir ações de mudança de estado a requisições POST é uma mitigação suficiente contra CSRF. Esta suposição é perigosamente incorreta. Um atacante pode facilmente forjar uma requisição POST de um domínio externo.

A técnica padrão envolve a criação de um formulário HTML em uma página controlada pelo atacante. O atributo `action` do formulário aponta para o *endpoint* vulnerável no *site* alvo, e o método é definido como POST. Os parâmetros da requisição são preenchidos usando campos `<input>` do tipo *hidden*, que são invisíveis para o usuário. Para automatizar o ataque e eliminar a necessidade de interação do usuário, um pequeno *script* JavaScript é adicionado à página para submeter o formulário assim que a página é carregada.

**O seguinte código ilustra um ataque CSRF baseado em POST para alterar o endereço de e-mail de um usuário**:

```html
<html>
  <body>
    <form action="https://site-vulneravel.com/email/alterar" method="POST">
      <input type="hidden" name="email" value="atacado@dominio-malicioso.net" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

Quando a vítima visita esta página, o formulário é submetido em segundo plano. O navegador anexa o *cookie* de sessão da vítima à requisição POST, e o servidor do *site* vulnerável processa a alteração de e-mail como se fosse uma ação legítima.

### Análise Comparativa: Vetores GET vs. POST

A escolha entre um vetor de ataque GET ou POST é uma decisão tática para o atacante, não uma defesa estratégica para a aplicação. A vulnerabilidade fundamental — a confiança do servidor no *cookie* de sessão como único validador de identidade e intenção — é independente do método HTTP. Enquanto o padrão RFC 2616 especifica que requisições GET devem ser "seguras" e idempotentes (ou seja, não devem alterar o estado do servidor), as aplicações que violam este princípio se expõem às formas mais simples de exploração de CSRF. No entanto, mesmo as aplicações que seguem o padrão e usam POST para ações de mudança de estado permanecem vulneráveis na ausência de proteções adicionais, como *tokens*.

**Tabela 2.1: Comparação de Vetores de Ataque CSRF GET vs. POST**

| Característica | Ataque CSRF Baseado em GET | Ataque CSRF Baseado em POST |
|----------------|----------------------------|-----------------------------|
| **Construção** | URL simples com parâmetros maliciosos. | Formulário HTML com campos ocultos e valores maliciosos. |
| **Entrega** | *Tags* `<img>`, `<a>`, `<iframe>`, CSS `url()`. | *Tag* `<form>` com *script* de auto-submissão. |
| **Interação do Usuário** | Pode ser de zero interação (ex: `<img>` no carregamento da página). | Pode ser de zero interação (*script* de auto-submissão). |
| **Furtividade** | Alta. Pode ser embutido de forma invisível (imagem 0x0 pixel). | Alta. O formulário pode ser oculto e submetido em segundo plano. |
| **Conformidade com RFC** | Viola a recomendação do RFC para que GET seja idempotente. | Alinha-se com o RFC para operações de mudança de estado. |
| **Padrão em *Frameworks*** | Frequentemente o primeiro tipo de CSRF a ser encontrado e corrigido. | A razão pela qual a proteção CSRF ainda é necessária mesmo que apenas POST seja usado para ações. |

## Entrega, Impacto e Precedentes do Mundo Real

### A Arte do Engano: Engenharia Social e Canais de Entrega de *Exploits*

A entrega de um *exploit* CSRF quase sempre depende de engenharia social para persuadir a vítima a interagir com o vetor de ataque. O atacante precisa induzir o navegador da vítima a fazer a requisição forjada. Os canais de entrega mais comuns incluem:

- **E-mails de *Phishing* e Mensagens Diretas**: Enviar um link malicioso disfarçado de conteúdo legítimo ou interessante por e-mail, *chat* ou redes sociais.
- **Injeção em *Sites* de Terceiros**: Plantar o *exploit* em um *site* popular que a vítima provavelmente visitará enquanto estiver autenticada na aplicação alvo. Isso é frequentemente feito em seções de comentários, fóruns ou postagens de *blog* que permitem a inserção de HTML limitado, como uma *tag* `<img>`.

### Quantificando o Dano: Impacto em Usuários Padrão vs. Contas Administrativas

O impacto potencial de um ataque CSRF bem-sucedido varia drasticamente dependendo dos privilégios da conta da vítima:

- **Impacto em Usuário Padrão**: Para um usuário comum, as consequências estão limitadas às ações que sua conta pode realizar. Isso pode incluir a transferência não autorizada de fundos, a alteração de credenciais de conta (e-mail, senha), a realização de compras ou a publicação de conteúdo indesejado em seu nome.
- **Impacto em Conta Administrativa**: Se a vítima for um administrador, o impacto pode ser catastrófico, levando ao comprometimento total da aplicação *web*. Um atacante pode forjar requisições para criar novas contas de administrador para si mesmo, excluir usuários, modificar configurações de segurança em todo o sistema ou extrair dados sensíveis de todos os usuários.

### Uma Ameaça Especializada: A Mecânica e as Implicações do *Login CSRF*

O *Login CSRF* é uma variante do ataque que inverte o modelo tradicional. Em vez de forçar um usuário autenticado a realizar uma ação, o atacante força um usuário não autenticado a fazer *login* em uma conta que o próprio atacante controla.

**O fluxo do ataque é o seguinte**:

1. O atacante cria uma conta no *site* alvo, *site-vulneravel.com*.
2. Em um *site* malicioso, *malicioso.com*, o atacante cria um formulário de *login* oculto e de auto-submissão com as credenciais de sua própria conta.
3. A vítima, que pode ou não ter uma conta no *site-vulneravel.com*, é induzida a visitar *malicioso.com*.
4. O formulário é submetido, e o navegador da vítima é autenticado no *site-vulneravel.com* como o atacante, recebendo um *cookie* de sessão para a conta do atacante.
5. A vítima, sem perceber que está usando a conta do atacante, pode então adicionar informações pessoais sensíveis, como detalhes de cartão de crédito, histórico de navegação ou dados de perfil.
6. Essas informações são salvas na conta do atacante no servidor. O atacante pode simplesmente fazer *login* mais tarde para coletar os dados inseridos pela vítima.

Este tipo de ataque transforma o CSRF de uma vulnerabilidade de mudança de estado em uma ferramenta de colheita de dados, destacando a necessidade de proteger até mesmo os formulários de *login* contra requisições forjadas.

### Estudos de Caso Históricos: Analisando as Vulnerabilidades de CSRF da Netflix (2006) e do YouTube (2008)

Antes que as proteções anti-CSRF se tornassem padrão em *frameworks* *web*, várias plataformas de grande porte eram vulneráveis. Dois casos notórios ilustram a simplicidade e o impacto desses ataques:

- **Netflix (2006)**: Uma vulnerabilidade de CSRF permitia que um atacante, usando uma simples *tag* `<img>` em qualquer página da *web*, forçasse o navegador de uma vítima logada a realizar ações na sua conta Netflix. As ações incluíam adicionar um DVD à fila de aluguel, alterar o endereço de entrega ou modificar as credenciais de *login* da conta.
- **YouTube (2008)**: Pesquisadores descobriram uma falha de CSRF que permitia a um atacante executar quase todas as ações disponíveis para um usuário. Isso incluía adicionar vídeos aos favoritos, gerenciar listas de amigos, enviar mensagens privadas e até mesmo sinalizar vídeos como inadequados, tudo em nome da vítima.

Esses casos demonstram como, na ausência de *tokens* ou outras verificações de intenção, funcionalidades críticas ficavam expostas a manipulação remota, dependendo apenas da sessão ativa do usuário.

## Defesas Além de *Tokens*: Uma Avaliação Crítica

### Verificando a Origem: A Promessa e o Perigo das Checagens dos Cabeçalhos *Origin* e *Referer*

Uma abordagem para mitigar CSRF é verificar os cabeçalhos HTTP *Origin* ou *Referer* para garantir que a requisição se origina do próprio domínio da aplicação. No entanto, esta é considerada uma defesa secundária e muitas vezes falha. As principais fraquezas desta abordagem são:

- **Omissão do Cabeçalho *Referer***: O cabeçalho *Referer* é opcional e pode ser suprimido por navegadores ou *proxies* por razões de privacidade. Algumas aplicações, ao não encontrarem o cabeçalho, pulam a validação por completo. Um atacante pode forçar essa omissão em sua página maliciosa usando a *tag* *meta* `<meta name="referrer" content="never">`.
- **Validação Ingênua**: A lógica de validação pode ser fraca. Se a aplicação apenas verifica se o domínio esperado começa a *string* do *Referer*, um atacante pode usar um subdomínio como *site-vulneravel.com.atacante.com*. Se a verificação apenas procura a presença do nome de domínio em qualquer lugar na URL, o atacante pode incluí-lo como um parâmetro de consulta: *atacante.com?site-vulneravel.com*.
- **Confiabilidade do Cabeçalho *Origin***: O cabeçalho *Origin* é considerado mais seguro, pois não pode ser alterado programaticamente por JavaScript. No entanto, ele não é enviado em todas as requisições de mesma origem, o que pode complicar a implementação de uma política de verificação consistente sem quebrar a funcionalidade legítima.

### Mitigação no Nível do Navegador: O Papel e as Limitações do Atributo de *Cookie* *SameSite*

O atributo de *cookie* *SameSite* é uma poderosa defesa no nível do navegador que instrui quando um *cookie* deve ser enviado com requisições de origem cruzada. Os valores disponíveis são:

- **SameSite=Strict**: Oferece a proteção mais forte, impedindo que o *cookie* seja enviado em todas as requisições de origem cruzada. Isso quebra efetivamente o CSRF, mas pode prejudicar a experiência do usuário, pois o usuário não será reconhecido ao navegar para o *site* a partir de um link externo.
- **SameSite=Lax**: É o padrão na maioria dos navegadores modernos. Ele permite que *cookies* sejam enviados em navegações de nível superior (ex: clicar em um link) que usam métodos HTTP "seguros" (como GET), mas os bloqueia em requisições de origem cruzada que usam métodos inseguros (como POST) e em requisições de sub-recursos (como `<img>` ou `<iframe>`). Isso mitiga muitos vetores de CSRF baseados em POST, mas ainda deixa a aplicação vulnerável a ataques CSRF baseados em GET.
- **SameSite=None**: Permite que o *cookie* seja enviado em todos os contextos de origem cruzada, mas exige que o atributo *Secure* também seja definido, o que significa que o *cookie* só será enviado por HTTPS.

A mudança do padrão dos navegadores para *SameSite=Lax* foi um marco na segurança da *web*, mitigando automaticamente uma grande classe de ataques CSRF. Essa mudança é um dos principais motivos pelos quais o CSRF foi reclassificado no OWASP Top 10, sendo absorvido pela categoria mais ampla de "Controle de Acesso Quebrado" (*Broken Access Control*), pois os *frameworks* e navegadores modernos agora oferecem proteção significativa por padrão.

### Defesas Modernas: Uma Análise dos Cabeçalhos de Requisição de Metadados *Fetch*

Os Cabeçalhos de Requisição de Metadados *Fetch* são um conjunto de cabeçalhos HTTP, prefixados com *Sec-Fetch-*, que fornecem aos servidores mais contexto sobre a origem de uma requisição. O cabeçalho mais relevante para a defesa contra CSRF é o *Sec-Fetch-Site*.

Este cabeçalho informa explicitamente ao servidor se uma requisição é:
- *same-origin*: A requisição vem da mesma origem.
- *same-site*: A requisição vem de um subdomínio do mesmo *site*.
- *cross-site*: A requisição vem de um *site* completamente diferente.
- *none*: A requisição foi iniciada diretamente pelo usuário (ex: digitando na barra de endereço ou clicando em um favorito).

Ao verificar o cabeçalho *Sec-Fetch-Site*, um servidor pode implementar uma política de isolamento de recursos robusta, rejeitando requisições *cross-site* para *endpoints* sensíveis que não deveriam ser acionados externamente. Isso oferece uma defesa mais confiável e explícita do que a verificação do *Referer*.

### O *Bypass* Definitivo: Como o XSS Neutraliza Todas as Formas de Proteção CSRF

Uma vulnerabilidade de *Cross-Site Scripting* (XSS) em qualquer parte de um *site* anula todas as outras defesas contra CSRF, incluindo as baseadas em *tokens*. Isso ocorre porque o CSRF depende da premissa de que um atacante opera a partir de uma origem externa e, portanto, está sujeito à Política de Mesma Origem (*Same-Origin Policy*), que o impede de ler respostas de outros domínios.

Uma vulnerabilidade XSS quebra essa premissa fundamental. Se um atacante puder injetar e executar JavaScript no domínio do *site* alvo, seu *script* passa a operar dentro da origem confiável. A partir dessa posição privilegiada, o *script* pode:

1. Fazer uma requisição *XMLHttpRequest* para uma página no mesmo domínio que contenha um formulário protegido por CSRF.
2. Como a requisição é de mesma origem, o *script* pode ler a resposta HTML.
3. Analisar o HTML da resposta para extrair o valor do *token* anti-CSRF válido e único da sessão.
4. Construir e submeter uma segunda requisição maliciosa (por exemplo, para transferir fundos), incluindo o *cookie* de sessão da vítima (que é enviado automaticamente) e o *token* CSRF válido que acabou de ser roubado.

O servidor recebe uma requisição da origem correta, com um *cookie* de sessão válido e um *token* CSRF válido, e não tem motivos para rejeitá-la. Portanto, o XSS permite um *bypass* completo das proteções CSRF baseadas em *token*, destacando a interconexão crítica entre diferentes classes de vulnerabilidades da *web*.

## Conclusão: A Necessidade de um Estado Imprevisível

### Síntese das Falhas das Defesas sem *Token*

A análise das defesas contra CSRF que não se baseiam em *tokens* revela suas fragilidades inerentes. A verificação dos cabeçalhos *Referer* e *Origin* é propensa a *bypasses* devido a implementações ingênuas e à possibilidade de omissão do cabeçalho. O atributo de *cookie* *SameSite*, embora seja uma melhoria significativa na segurança padrão dos navegadores, oferece proteção incompleta no modo *Lax* e pode impactar a usabilidade no modo *Strict*. Os cabeçalhos de Metadados *Fetch* representam uma abordagem moderna e mais robusta, mas ainda dependem de uma implementação correta no lado do servidor. Todas essas medidas, embora úteis como camadas de defesa em profundidade, não resolvem o problema fundamental: a previsibilidade da requisição forjada.

### O Padrão Ouro: Por Que os *Tokens* Sincronizadores e os *Cookies* de Submissão Dupla são a Solução Definitiva

As defesas baseadas em *tokens*, como o Padrão de *Token* Sincronizador e o Padrão de *Cookie* de Submissão Dupla, são consideradas o padrão ouro porque introduzem um elemento de estado imprevisível que é único para a sessão do usuário. Ao exigir que cada requisição de mudança de estado inclua este segredo, que um atacante em uma origem diferente não pode adivinhar ou ler, a aplicação garante que a requisição não foi forjada. Este *token* serve como prova da intenção do usuário, quebrando a premissa central do ataque CSRF, que depende de requisições contendo apenas credenciais enviadas automaticamente, como *cookies*.

### Recomendações para uma Estratégia de Defesa em Profundidade

Uma estratégia de segurança robusta contra CSRF deve ser multifacetada, priorizando defesas baseadas em *tokens* e complementando-as com mecanismos de mitigação no nível do navegador e do servidor.

**Defesa Primária**:
- Implementar o Padrão de *Token* Sincronizador para aplicações *stateful*, onde um *token* único é gerado, armazenado na sessão do servidor e validado a cada requisição de mudança de estado.
- Para aplicações *stateless*, utilizar o Padrão de *Cookie* de Submissão Dupla Assinado, onde um *token* é enviado em um *cookie* e em um parâmetro de requisição, e o servidor verifica se ambos correspondem.

**Defesas Secundárias (Defesa em Profundidade)**:
- Utilizar o atributo de *cookie* *SameSite*, configurando-o como *Strict* sempre que possível, ou *Lax* como um padrão seguro.
- Validar os cabeçalhos *Origin* e/ou *Referer*, mas nunca como a única linha de defesa.
- Exigir reautenticação do usuário para operações altamente sensíveis, como alteração de senha ou autorização de grandes transações financeiras.
- Manter uma defesa rigorosa contra vulnerabilidades de *Cross-Site Scripting* (XSS), pois uma única falha de XSS pode ser usada para contornar todas as proteções CSRF.