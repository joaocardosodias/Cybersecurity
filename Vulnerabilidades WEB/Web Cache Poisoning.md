# Web Cache Poisoning: Uma Análise Aprofundada de Mecanismos, Vetores de Ataque e Estratégias de Mitigação

## As Fundações do *Web Caching* e a Gênese do Envenenamento

### A Função Crítica do *Caching* na *Web* Moderna

O *caching* é uma técnica fundamental de otimização de desempenho que sustenta a *web* moderna. Em sua essência, um *cache* da *web* atua como um intermediário entre o usuário final e o servidor de origem da aplicação (*back-end*). Ele armazena cópias temporárias de respostas a requisições HTTP, como páginas HTML, arquivos CSS, *scripts* JavaScript e imagens. Os principais benefícios são a redução da latência, a diminuição da carga no servidor de aplicação e a economia de custos de rede. Sem o *caching*, cada requisição de cada usuário teria que ser processada individualmente pelo *back-end*, o que sobrecarregaria rapidamente os servidores, especialmente em *sites* de alto tráfego, resultando em uma experiência de usuário degradada.

É crucial diferenciar os tipos de *caches*, pois isso determina o escopo e o impacto potencial de um ataque de envenenamento:

- **Caches Privados**: Servem a um único usuário. O exemplo mais comum é o *cache* do navegador. Embora o envenenamento de um *cache* privado seja possível, o impacto é limitado a esse usuário individual até que a entrada de *cache* seja limpa.
- **Caches Compartilhados**: Servem a múltiplos usuários e são o alvo principal dos ataques de *Web Cache Poisoning* (WCP). Estes incluem *caches* de *proxy* reverso (como Varnish ou Nginx) implantados por uma organização e Redes de Distribuição de Conteúdo (CDNs) em grande escala, como Cloudflare, Akamai ou Fastly. As CDNs possuem servidores distribuídos geograficamente para entregar conteúdo a partir da "borda" da rede, mais perto do usuário. O impacto de envenenar um *cache* compartilhado é massivamente amplificado, pois uma única resposta maliciosa pode ser servida a milhares ou milhões de usuários.

A própria existência do *Web Cache Poisoning* expõe um conflito arquitetônico inerente entre desempenho e segurança. Para maximizar o desempenho, os sistemas de *cache* são projetados para serem rápidos e eficientes, fazendo suposições amplas sobre quais requisições são "equivalentes" para aumentar a taxa de acertos de *cache* (a proporção de requisições servidas a partir do *cache*). A segurança, por outro lado, exige decisões contextuais e detalhadas. O WCP explora a lacuna entre o modelo de mundo simplificado do *cache* e a complexa realidade da aplicação de *back-end* que ele serve. A otimização do desempenho leva ao uso de uma "chave de *cache*" simplificada, que cria um ponto cego que os atacantes podem explorar.

### Definindo o *Web Cache Poisoning* (WCP)

O *Web Cache Poisoning* é uma técnica avançada na qual um adversário explora o comportamento de um servidor *web* e sua camada de *cache* para injetar uma resposta HTTP prejudicial no *cache*. Essa resposta "envenenada" é então servida a qualquer usuário que solicite o mesmo recurso, transformando efetivamente o *cache* em um sistema de distribuição para o ataque.

O principal perigo do WCP reside em sua capacidade de amplificar uma vulnerabilidade. Uma única requisição maliciosa de um atacante pode comprometer um recurso em *cache* que é subsequentemente servido a um grande número de usuários legítimos, sem qualquer interação adicional do atacante ou das vítimas. O impacto é, portanto, diretamente proporcional à popularidade da página envenenada; envenenar a página inicial de um grande *site* de notícias, por exemplo, pode afetar milhares de usuários por minuto.

### Uma Distinção Crucial: WCP vs. *Web Cache Deception* (WCD)

Embora ambos os ataques abusem dos mecanismos de *cache*, seus objetivos e mecanismos são fundamentalmente diferentes.

- **Web Cache Poisoning (WCP)**: O objetivo do atacante é injetar conteúdo malicioso no *cache*. O objetivo é fazer com que o *cache* sirva dados prejudiciais, como um *payload* de JavaScript, a outros usuários. O atacante envia uma requisição que provoca uma resposta maliciosa do servidor, que é então armazenada no *cache*.
- **Web Cache Deception (WCD)**: O objetivo do atacante é enganar o *cache* para que ele armazene conteúdo sensível e específico do usuário e, em seguida, recuperá-lo. O atacante não injeta seu próprio conteúdo; ele faz com que os dados privados de uma vítima sejam armazenados publicamente em *cache*. Isso é tipicamente realizado enganando uma vítima para que visite uma URL maliciosa que o *cache* interpreta erroneamente como uma requisição para um ativo estático e cacheável (por exemplo, *https://exemplo.com/conta/perfil.css*). O *cache* armazena a página de perfil da vítima, e o atacante pode então acessá-la nessa URL.

Em resumo, o WCP visa injetar conteúdo malicioso para que outros o recebam, enquanto o WCD visa expor o conteúdo privado de uma vítima para que o atacante o recupere.

## A Mecânica do Ataque: Chaves de *Cache* e Entradas Não Chaveadas

### A Chave de *Cache*: A Impressão Digital de uma Requisição

Uma chave de *cache* (*cache key*) é um identificador único gerado pela camada de *cache* a partir de componentes específicos de uma requisição HTTP recebida. O *cache* usa essa chave para determinar se possui uma resposta armazenada para uma requisição "equivalente".

Por padrão, a chave de *cache* é tipicamente construída a partir do método da requisição (geralmente GET), do cabeçalho *Host* e do caminho da requisição, incluindo a *string* de consulta. Se uma requisição recebida tiver os mesmos valores para esses componentes que uma requisição anterior, o *cache* a considera um "acerto de *cache*" (*cache hit*) e serve a resposta armazenada. Por exemplo, o Amazon CloudFront, por padrão, usa o nome de domínio da distribuição e o caminho da URL em sua chave de *cache*, mas permite a personalização para incluir outros elementos como *strings* de consulta, cabeçalhos HTTP e *cookies*.

### Entradas Não Chaveadas: O Calcanhar de Aquiles do *Caching*

Entradas não chaveadas (*unkeyed inputs*) são partes de uma requisição HTTP que são ignoradas pelo *cache* ao construir a chave de *cache*, mas são utilizadas pela aplicação de *back-end* para gerar a resposta. A vulnerabilidade nasce dessa incompatibilidade fundamental: o *cache* vê duas requisições como idênticas porque seus componentes chaveados correspondem, mas a aplicação de *back-end* as vê como diferentes porque processa uma entrada não chaveada, levando a duas respostas diferentes para a mesma chave de *cache*.

As entradas não chaveadas mais comuns incluem:

- **Cabeçalhos HTTP**: Muitas aplicações usam cabeçalhos não padrão como *X-Forwarded-Host*, *X-Forwarded-Scheme*, *X-Original-URL*, ou mesmo cabeçalhos padrão como *Accept-Language* e *User-Agent* para alterar o conteúdo. Se estes não fizerem parte da chave de *cache*, eles se tornam um vetor de ataque principal.
- **Parâmetros de Consulta**: Por razões de desempenho, os *caches* podem ser configurados para ignorar toda a *string* de consulta ou parâmetros específicos (como os de rastreamento *utm_*). Se a aplicação reflete esses parâmetros na resposta, eles podem ser usados para envenenamento.
- **Cookies**: Um *cookie* pode determinar o idioma ou o estado de uma página. Se o *cache* ignora o cabeçalho *Cookie*, mas a aplicação o utiliza, um atacante pode envenenar o *cache* para todos os usuários.

A chave de *cache* é, na verdade, uma abstração projetada para simplificar a identidade complexa de um recurso da *web*. O WCP explora a "permeabilidade" dessa abstração. A vulnerabilidade existe porque a abstração é imperfeita e não leva em conta todas as variáveis que podem definir o estado final do recurso. Um recurso da *web* não é definido apenas por sua URL; seu estado final pode depender de preferências de idioma (*Accept-Language*), tipo de dispositivo (*User-Agent*), instruções especiais de *proxy* (*X-Forwarded-Host*) e muito mais. Uma chave de *cache* perfeita incluiria todas essas variáveis, mas isso seria impraticável e levaria a uma taxa de acertos de *cache* muito baixa, anulando o propósito do *cache*. Consequentemente, os projetistas de sistemas criam uma abstração simplificada, assumindo implicitamente que "apenas essas entradas chaveadas importam". O WCP prova que essa suposição é frequentemente falsa, pois as entradas não chaveadas que a abstração ignora "vazam" e influenciam a resposta final.

### A Metodologia de Envenenamento em Três Fases

Este processo canônico, delineado pela PortSwigger, fornece um *framework* claro para a construção de um ataque.

1. **Fase 1: Identificar e Avaliar Entradas Não Chaveadas**: O primeiro passo é sondar metodicamente a aplicação para encontrar entradas que não fazem parte da chave de *cache*, mas que ainda afetam a resposta. Isso envolve o envio de requisições com vários cabeçalhos e parâmetros e a observação de quaisquer alterações no corpo ou nos cabeçalhos da resposta. O uso de um "*cache buster*" (um parâmetro de consulta único) é crucial durante esta fase para garantir que cada requisição receba uma resposta nova do *back-end*, contornando quaisquer entradas de *cache* existentes.
2. **Fase 2: Provocar uma Resposta Prejudicial**: Uma vez que uma entrada não chaveada que é refletida ou processada de forma insegura pela aplicação é encontrada, o atacante cria um *payload* para gerar uma resposta prejudicial. Este *payload* pode ser um *script* XSS, uma URL de redirecionamento ou dados que causam um erro.
3. **Fase 3: Fazer com que a Resposta Seja Armazenada em *Cache***: Este é o passo final e muitas vezes o mais delicado. O atacante deve enviar sua requisição maliciosa no momento certo — tipicamente logo após a expiração da entrada de *cache* anterior para aquele recurso — para garantir que sua resposta envenenada seja a que será armazenada. Em seguida, ele verifica o envenenamento enviando uma requisição limpa (sem o *payload*) e verificando se a resposta envenenada é servida de volta.

## Vetores de Exploração e Cenários de Ataque Práticos

### Envenenamento via Cabeçalhos HTTP Não Chaveados

Este é o vetor mais comum de WCP. A aplicação confia e utiliza um cabeçalho HTTP não padrão (muitas vezes injetado por um *proxy* *upstream*) para gerar conteúdo, como URLs de recursos ou redirecionamentos. Se este cabeçalho não for chaveado, um atacante pode fornecer seu próprio valor para envenenar a resposta.

Um exemplo clássico envolve o cabeçalho *X-Forwarded-Host*. Uma aplicação pode usar este cabeçalho para gerar URLs absolutas para seus ativos. Um atacante envia uma requisição com *X-Forwarded-Host: site-malicioso.com*. O *back-end* gera uma resposta como `<script src="https://site-malicioso.com/ativo.js">`. Se esta resposta for armazenada em *cache*, todos os usuários subsequentes que visitarem a página legítima tentarão carregar um *script* malicioso do servidor do atacante. Outros cabeçalhos como *X-Original-URL*, *X-Rewrite-URL* e *X-Forwarded-Scheme* podem ser abusados de forma semelhante para acionar redirecionamentos, alterar o protocolo (HTTP/HTTPS) ou modificar o comportamento de roteamento.

### Manipulação de Parâmetros de Consulta e *Cookies*

Alguns *caches* são configurados para ignorar toda a *string* de consulta para maximizar os acertos de *cache* em uma URL base. Se a aplicação reflete um parâmetro da *string* de consulta (por exemplo, um termo de busca), um atacante pode envenenar a URL base com um *payload* na *string* de consulta. Um usuário legítimo que visita a URL base (sem a *string* de consulta) receberá a resposta envenenada.

Da mesma forma, uma aplicação pode usar um *cookie* (por exemplo, *lang=es*) para servir uma versão em espanhol de uma página. Se o cabeçalho *Cookie* não fizer parte da chave de *cache*, um atacante pode solicitar a versão em espanhol. Essa resposta é armazenada em *cache* para a URL principal, e agora todos os usuários (incluindo falantes de inglês) receberão a página em espanhol. Isso pode ser escalado injetando um *payload* em um valor de *cookie* que é refletido na resposta.

### Técnicas Avançadas e Falhas de Implementação

Além dos vetores mais diretos, existem técnicas mais sutis que exploram falhas específicas na implementação do *cache*:

- **Requisições "Fat GET"**: Alguns *frameworks* processam indevidamente requisições GET que contêm um corpo. Se o *cache* ignora o corpo da requisição (como deveria para requisições GET), mas a aplicação o processa e reflete seu conteúdo na resposta, isso cria um vetor de envenenamento.
- **Parameter Cloaking**: Esta técnica explora discrepâncias na forma como um *cache* e um servidor de *back-end* analisam os parâmetros de consulta, especialmente com delimitadores como *;* ou *&*. Um atacante pode criar uma URL como */?param1=foo;injetado=bar*. O *cache* pode ver isso como um único parâmetro, enquanto o *framework* de *back-end* (por exemplo, Ruby on Rails) o analisa como dois parâmetros separados. Isso permite ao atacante "esconder" um parâmetro da chave de *cache* e usá-lo para envenenar a resposta.
- **Normalização da Chave de *Cache***: Os *caches* frequentemente "normalizam" as entradas antes de criar a chave. Por exemplo, um *cache* pode remover o número da porta do cabeçalho *Host* (*Host: exemplo.com:8080* torna-se *exemplo.com* na chave). Um atacante pode usar a porta para injetar um *payload* que afeta a resposta do *back-end*, enquanto a chave de *cache* permanece "normal" e corresponde às requisições de outros usuários.
- **HTTP Request Smuggling (HRS) e *Response Splitting***: Embora sejam vulnerabilidades distintas, podem ser vetores poderosos para WCP. Um atacante pode usar HRS para contrabandear uma segunda requisição maliciosa para o *back-end*. A resposta a essa requisição contrabandeada pode ser mapeada incorretamente pelo *cache* para uma requisição legítima de outro usuário, envenenando o *cache*.

### Encadeamento de Vulnerabilidades: O Conceito de "*Gadget*"

O WCP é mais poderoso quando não é um ataque isolado, mas um mecanismo para entregar e escalar outra vulnerabilidade. Essa vulnerabilidade ou comportamento secundário é conhecido como "*gadget*". Um *gadget* pode ser qualquer comportamento do lado do cliente que processa entradas do servidor, como XSS refletido, um redirecionamento aberto ou manipulação de dados baseada no DOM. Muitas vezes, esses *gadgets* são descartados como "inexploráveis" porque exigem uma requisição malformada que um navegador padrão não enviaria ou uma interação significativa do usuário.

O WCP torna esses *gadgets* "inexploráveis" em exploráveis. O atacante envia a requisição malformada diretamente ao servidor para acionar o *gadget*. A resposta envenenada resultante é armazenada em *cache*. Agora, qualquer usuário que visite a URL normal e legítima recebe o *payload*, e o *gadget* é executado em seu navegador. Isso transforma efetivamente um XSS refletido de baixo impacto em um XSS armazenado de alto impacto.

**Tabela: Vetores de Ataque do WCP**

| Vetor de Ataque | Mecanismo Central | Exemplo de *Payload* (Requisição) | Pré-requisito Chave |
|-----------------|-------------------|----------------------------------|---------------------|
| **Cabeçalho Não Chaveado** | A aplicação usa um cabeçalho ignorado pela chave de *cache* para gerar conteúdo de resposta. | `GET / HTTP/1.1`<br>`Host: site.com`<br>`X-Forwarded-Host: evil.com` | A aplicação deve refletir o valor do cabeçalho sem sanitização; o cabeçalho deve ser não chaveado. |
| **Parâmetro de Consulta Não Chaveado** | O *cache* ignora um ou todos os parâmetros de consulta, mas a aplicação os reflete na resposta. | `GET /?utm_content='"><script>alert(1)</script>` | O parâmetro de consulta deve ser não chaveado e refletido de forma insegura pela aplicação. |
| **Parameter Cloaking** | Discrepância de *parsing* entre o *cache* e o *back-end* sobre delimitadores de parâmetros (ex: ;). | `GET /?param1=foo;injetado=bar` | O *cache* interpreta a *string* como um único parâmetro, enquanto o *back-end* a divide em múltiplos. |
| **"Fat GET"** | O *cache* ignora o corpo de uma requisição GET, mas a aplicação o processa e reflete na resposta. | `GET /recurso HTTP/1.1`<br>`Host: site.com`<br>`...`<br>`param=payload` | A aplicação deve aceitar e processar corpos em requisições GET. |
| **Normalização da Chave de *Cache*** | O *cache* normaliza uma entrada (ex: remove a porta do *Host*) antes de criar a chave. | `GET / HTTP/1.1`<br>`Host: site.com:1337<script>...` | A aplicação deve usar a versão não normalizada da entrada, enquanto o *cache* usa a versão normalizada. |

## O Impacto Multifacetado do *Web Cache Poisoning*

### Escalando Ataques do Lado do Cliente: De Refletido a Armazenado

O impacto mais significativo do WCP é sua capacidade de servir um *payload* de ataque do lado do cliente, como *Cross-Site Scripting* (XSS), para um público amplo a partir de um domínio confiável. Ele atua como uma ponte, transformando um XSS refletido (que exige enganar um usuário para clicar em um *link*) em um XSS armazenado de fato (que é executado para qualquer usuário que visite uma página envenenada). Isso aumenta drasticamente a gravidade e a explorabilidade da vulnerabilidade original.

Um exemplo prático é a exploração de uma vulnerabilidade XSS baseada no DOM através do WCP. Considere o seguinte cenário:

- **O *Gadget***: Uma aplicação possui um *script* (*geolocate.js*) que busca um arquivo JSON do servidor e processa seu conteúdo de forma insegura, inserindo-o no DOM.
- **O Vetor de Envenenamento**: A URL para este arquivo JSON é gerada dinamicamente usando o cabeçalho não chaveado *X-Forwarded-Host*.
- **O Ataque**: O atacante hospeda um arquivo JSON malicioso em seu próprio servidor contendo um *payload* XSS, como `{"country": "<img src=1 onerror=alert(document.cookie)>"}`.
- **Execução e *Cache***: O atacante envia uma requisição para a página inicial do alvo com o cabeçalho *X-Forwarded-Host* apontando para seu servidor. O *back-end* gera uma resposta onde o *script* *geolocate.js* é instruído a buscar o JSON do servidor do atacante. Esta resposta envenenada é armazenada em *cache*.
- **Impacto**: Qualquer usuário subsequente que visite a página inicial recebe a resposta em *cache*. Seu navegador executa o *script*, que busca o JSON malicioso e injeta o *payload* XSS no DOM da página, permitindo que o atacante roube *cookies* ou realize outras ações.

O perigo real do WCP reside em sua capacidade de armar a confiança do usuário e do navegador em um domínio legítimo. Como o *payload* malicioso é entregue a partir de uma fonte confiável, ele contorna muitas defesas convencionais e suspeitas do usuário. Do ponto de vista do navegador, o *script* é legítimo e de primeira parte, recebendo todos os privilégios associados, como acesso a *cookies* e a capacidade de fazer requisições autenticadas para as APIs do *site*. Isso subverte completamente o modelo de segurança da *web*, pois o usuário vê a URL correta e o cadeado SSL, dando-lhe uma falsa sensação de segurança.

### Negação de Serviço Envenenada por *Cache* (CPDoS)

Um atacante pode identificar uma entrada não chaveada que, quando manipulada com um valor malformado, faz com que o servidor de *back-end* retorne uma página de erro (por exemplo, *400 Bad Request*, *500 Internal Server Error*). Se esta resposta de erro for cacheável, o atacante pode envenenar a entrada de *cache* de um recurso legítimo com a página de erro. Consequentemente, todos os usuários subsequentes que tentarem acessar esse recurso receberão a página de erro em *cache*, tornando o recurso ou até mesmo o *site* inteiro indisponível até que a entrada de *cache* expire. Uma única requisição pode ser suficiente para bloquear o acesso para um grande número de usuários. Vetores comuns incluem o envio de um cabeçalho superdimensionado (*HHO*), um cabeçalho com metacaracteres ilegais (*HMC*) ou um que aciona um *loop* de redirecionamento.

### Contornando Proteções de Segurança e Facilitando o Roubo de Dados

O WCP pode ser usado para contornar outros mecanismos de segurança. Ao manipular o conteúdo em *cache*, um atacante pode contornar proteções contra XSS e *Cross-Site Request Forgery* (CSRF). Por exemplo, um atacante pode usar o WCP para entregar um *script* que lê o conteúdo de uma página, extrai um *token* CSRF válido e o envia para um domínio controlado pelo atacante, que pode então usar esse *token* para realizar um ataque CSRF. Além disso, ao envenenar uma página com um *script* malicioso, um atacante pode exfiltrar quaisquer dados sensíveis visíveis naquela página ou acessíveis à sessão do usuário, incluindo informações pessoais, chaves de API ou *tokens* de sessão.

## Detecção, Análise e Ferramentas

### Metodologia de Detecção Manual

A detecção de WCP não pode ser realizada analisando um único par de requisição-resposta isoladamente. Requer uma análise comparativa e com estado, o que a torna um desafio para *scanners* de vulnerabilidade tradicionais e um caso de uso perfeito para ferramentas especializadas.

1. **Identificar Comportamento de *Cache***: O primeiro passo é confirmar que o *cache* está em uso, procurando por cabeçalhos de resposta relacionados a *cache*, como *X-Cache*, *CF-Cache-Status*, *Age*, *Cache-Control* ou cabeçalhos específicos do servidor como *X-Varnish*. Um *status* *HIT* indica uma resposta em *cache*, enquanto *MISS* indica uma resposta nova do *back-end*. Encontrar uma maneira confiável de obter *feedback* sobre acertos/erros de *cache* é crucial; isso é conhecido como "oráculo de *cache*".
2. **Sondar Entradas Não Chaveadas**:
   - Use um *cache buster* (um parâmetro de consulta único, como *?cb=12345*) em cada requisição para garantir que você está sempre atingindo o servidor de *back-end*.
   - Injete e observe: Adicione potenciais entradas não chaveadas (por exemplo, *X-Forwarded-Host: teste.com*) à requisição e observe se a resposta muda.
   - Confirme a falta de chaveamento: Remova o *cache buster*, mas mantenha o cabeçalho injetado. Envie a requisição duas vezes. Se a primeira requisição for um *MISS* e a segunda for um *HIT* enquanto o valor injetado ainda estiver refletido, a entrada não é chaveada e a página é potencialmente vulnerável.

### Ferramentas Automatizadas e Assistidas

- **PortSwigger Param Miner**: Uma extensão para o Burp Suite projetada especificamente para essa tarefa. Ela automatiza o processo de descoberta de entradas não chaveadas, enviando um grande número de requisições com vários cabeçalhos e parâmetros e sinalizando qualquer um que afete a resposta.
- **Web Cache Vulnerability Scanner (WCVS)**: Uma ferramenta de linha de comando de código aberto dedicada à detecção de WCP e WCD. Ela suporta uma ampla gama de técnicas conhecidas, incluindo envenenamento de cabeçalho/parâmetro não chaveado, *parameter cloaking*, *Fat GET*, *HHO*, *HMC* e mais.
- **Scanners Comerciais**: *Scanners* dinâmicos de nível empresarial (*DAST*) de fornecedores como Tenable e Invicti também estão incorporando verificações para várias formas de envenenamento de *cache*.

## Estratégias de Mitigação e Melhores Práticas Defensivas

### Configuração Robusta da Chave de *Cache*: A Defesa Primária

A defesa mais eficaz é garantir que a chave de *cache* represente com precisão todas as entradas que podem variar a resposta. Se uma entrada afeta a resposta, ela DEVE estar na chave de *cache*.

O cabeçalho de resposta *Vary* é o mecanismo padrão para conseguir isso. Ele informa ao *cache* quais cabeçalhos de requisição (além do *host* e caminho padrão) devem ser incluídos na chave de *cache*. Por exemplo, *Vary: X-Forwarded-Host, Accept-Language* instrui o *cache* a criar entradas de *cache* separadas para cada combinação única desses valores de cabeçalho. Esta é a maneira mais direta e correta de mitigar o envenenamento baseado em cabeçalhos. Para outras entradas, como parâmetros de consulta ou *cookies*, a camada de *cache* deve ser explicitamente configurada para incluí-las na chave de *cache* se forem usadas pelo *back-end*.

### Princípios de Design Seguro

- **Armazenar em *Cache* Apenas Conteúdo Estático**: A estratégia mais simples e segura é desativar completamente o *cache* para páginas que geram respostas dinâmicas. Armazene em *cache* apenas ativos verdadeiramente estáticos, como arquivos CSS, JS e imagens que nunca mudam com base na entrada do usuário.
- **Nunca Confie na Entrada do Usuário**: Trate todas as entradas, especialmente os cabeçalhos HTTP, como não confiáveis. Elas devem ser validadas, sanitizadas ou rejeitadas antes de serem usadas para gerar o conteúdo da resposta.
- **Restringir Funcionalidades Perigosas**: Se a aplicação não precisa suportar cabeçalhos não padrão ou requisições GET com corpos, essa funcionalidade deve ser desativada na camada do servidor *web* ou do *proxy*.

### Defesa em Profundidade

- **Web Application Firewalls (WAFs)**: Um WAF pode ajudar filtrando requisições com *payloads* maliciosos conhecidos, mas é uma defesa secundária e pode não entender as nuances do comportamento do *cache*.
- **Monitoramento**: Monitore regularmente os avisos de segurança para seus *frameworks* e *software* de *cache*. Anomalias no desempenho do *cache* ou nas taxas de erro podem indicar uma tentativa de envenenamento.
- **Correção de Vulnerabilidades**: Corrigir vulnerabilidades do lado do cliente, como XSS refletido, mesmo que pareçam inexploráveis, é crítico, pois o WCP pode fornecer o elo que faltava para torná-las exploráveis.

**Tabela: Técnicas de Mitigação**

| Técnica de Mitigação | Camada de Implementação | Descrição | Ideal Para |
|----------------------|-------------------------|-----------|------------|
| **Cabeçalho *Vary*** | *Cache* / *Proxy* | Informa ao *cache* para incluir cabeçalhos de requisição adicionais na chave de *cache*. | Mitigar envenenamento de qualquer cabeçalho de requisição não chaveado. |
| **Chaveamento de *Cache* Estrito** | *Cache* / *Proxy* | Configurar explicitamente a camada de *cache* para incluir parâmetros de consulta ou *cookies* na chave. | Prevenir envenenamento via parâmetros de consulta ou *cookies* não chaveados. |
| **Desativar *Cache* para Páginas Dinâmicas** | Aplicação / *Cache* | Usar *Cache-Control: no-store* ou regras de *cache* para evitar o armazenamento de respostas dinâmicas. | A estratégia mais segura para conteúdo que depende da entrada do usuário. |
| **Validação de Entrada** | Aplicação | Sanitizar ou rejeitar todas as entradas do usuário (cabeçalhos, parâmetros) antes de usá-las. | Prevenir que *payloads* maliciosos sejam refletidos na resposta em primeiro lugar. |
| **Restringir "Fat GET"** | Servidor *Web* / *Proxy* | Configurar o servidor para rejeitar requisições GET que contenham um corpo. | Bloquear o vetor de ataque "*Fat GET*". |

## Conclusão: O Paradigma do *Caching* e a Segurança na *Web*

O *Web Cache Poisoning* não é uma simples falha de programação, mas uma vulnerabilidade sistêmica que nasce da interação e, crucialmente, das suposições desalinhadas entre as camadas de *cache* e as aplicações de *back-end*. O vetor de ataque é a entrada não chaveada, e o impacto é a amplificação de outras vulnerabilidades para uma base de usuários ampla, transformando falhas de baixo risco em ameaças de alta gravidade.

A defesa contra o WCP exige uma postura de segurança holística. Não basta proteger o código da aplicação isoladamente. Desenvolvedores, equipes de segurança e equipes de infraestrutura/DevOps devem colaborar para garantir que toda a pilha de entrega da aplicação seja configurada de forma segura e consistente. A evolução dos ataques de WCP, desde o simples abuso de cabeçalhos até explorações complexas de falhas de implementação e peculiaridades de normalização, demonstra que, à medida que as arquiteturas da *web* se tornam mais complexas e em camadas, também se tornam as superfícies de ataque. Compreender e proteger as costuras entre essas camadas é fundamental para o futuro da segurança de aplicações *web*.