# Subdomain Takeover: Uma Análise Abrangente de uma Ameaça Persistente à Segurança na Nuvem

## Seção 1: Introdução ao Subdomain Takeover

### 1.1 Definindo a Vulnerabilidade: Além do "DNS Pendente"

O Subdomain Takeover (Tomada de Controle de Subdomínio) representa uma ameaça de alta severidade para organizações, originada de uma desconexão fundamental entre a resolução do Sistema de Nomes de Domínio (DNS) e o provisionamento de recursos em nuvem ou de terceiros. Em sua essência, a vulnerabilidade ocorre quando um registro DNS, como um CNAME, aponta para um recurso externo que foi desprovisionado, excluído ou nunca foi reivindicado, mas o registro DNS em si não foi removido da zona DNS da organização. Esses registros são comumente referidos como "DNS pendentes" (dangling DNS) ou "registros órfãos".

A exploração dessa vulnerabilidade não envolve a quebra do protocolo DNS, mas sim a exploração de uma falha no gerenciamento do ciclo de vida dos ativos digitais. O processo pode ser entendido como uma exploração em duas etapas: primeiro, a existência de um registro DNS legítimo que aponta para um recurso externo; segundo, a capacidade de um invasor reivindicar legitimamente esse recurso alvo. Quando um invasor reivindica o recurso desprovisionado (por exemplo, criando um bucket de armazenamento em nuvem com o mesmo nome do que foi excluído), todo o tráfego destinado ao subdomínio legítimo é redirecionado para o serviço agora controlado pelo invasor.

O ciclo de vida típico de uma vulnerabilidade de Subdomain Takeover se desenrola da seguinte forma:

- **Criação**: Uma organização provisiona um recurso em um provedor de nuvem (por exemplo, um Azure App Service em `app.azurewebsites.net`) e cria um registro CNAME em sua zona DNS (por exemplo, `loja.empresa.com`) para apontar para esse recurso.
- **Desprovisionamento**: Em um momento posterior, o recurso em nuvem é excluído, seja por fim de um projeto, migração ou limpeza de infraestrutura. No entanto, o processo de desprovisionamento falha em incluir a remoção do registro CNAME correspondente da zona DNS.
- **Estado Pendente**: O registro DNS para `loja.empresa.com` agora é um "ponteiro pendente". Ele ainda existe e é resolvido publicamente, mas aponta para um destino que não existe mais. O subdomínio está vulnerável.
- **Tomada de Controle**: Um agente malicioso descobre esse registro pendente e provisiona um novo recurso no mesmo provedor de nuvem, reivindicando o mesmo nome de host (`app.azurewebsites.net`). Como o provedor de nuvem agora vê uma reivindicação legítima para esse nome de host, ele começa a rotear o tráfego para o recurso do invasor.

### 1.2 A Superfície de Ataque Moderna: Como a Proliferação da Nuvem e do SaaS Amplifica o Risco

A prevalência do Subdomain Takeover aumentou drasticamente com a adoção generalizada de infraestruturas em nuvem efêmeras e orientadas por API (como Amazon Web Services, Microsoft Azure e Google Cloud Platform) e a dependência de uma vasta gama de plataformas de Software como Serviço (SaaS), como GitHub, Heroku, Shopify e HubSpot. Essa mudança de paradigma na forma como as aplicações são construídas e implantadas expandiu massivamente a superfície de ataque digital das organizações.

A velocidade e a agilidade proporcionadas pelas práticas de DevOps e pela infraestrutura como código (IaC) permitem que as equipes criem e destruam recursos em um ritmo sem precedentes. No entanto, essa velocidade muitas vezes ultrapassa a maturidade dos processos de governança e gerenciamento de ativos. Em ambientes de desenvolvimento rápido, subdomínios e recursos associados são criados para testes, campanhas de marketing de curta duração ou funcionalidades específicas e, em seguida, esquecidos. O resultado é um acúmulo de "dívida de processo", manifestada como um cemitério de registros DNS órfãos que apontam para recursos desativados.

Essa vulnerabilidade se enquadra firmemente no lado do cliente do "modelo de responsabilidade compartilhada" da segurança em nuvem. Os provedores de nuvem são responsáveis pela segurança *da* nuvem, mas os clientes são responsáveis pela segurança *na* nuvem. Um registro DNS pendente é uma misconfiguração do cliente, tornando a organização, e não o provedor, responsável por suas consequências. A natureza sistêmica desse problema indica que, para muitas organizações, os processos de segurança e higiene de ativos digitais não conseguiram acompanhar a velocidade da inovação e da implantação. A existência de um grande número de registros DNS pendentes pode ser vista como um indicador principal de uma gestão de ciclo de vida de ativos imatura.

### 1.3 Visão Geral do Impacto: De Simples Desfiguração a Comprometimento Total de Contas

As consequências de um Subdomain Takeover bem-sucedido variam drasticamente, dependendo do contexto do subdomínio comprometido. Em sua forma mais branda, o ataque pode resultar em danos à reputação por meio da desfiguração (defacement) do site, onde um invasor substitui o conteúdo legítimo por mensagens maliciosas ou embaraçosas. No entanto, o verdadeiro perigo reside no potencial de encadear essa vulnerabilidade com outros ataques, transformando um ponto de entrada aparentemente de baixo impacto em uma violação de segurança crítica.

Um invasor que controla um subdomínio confiável pode lançar campanhas de phishing altamente convincentes, distribuir malware a partir de uma fonte aparentemente legítima e realizar a exfiltração de dados confidenciais, como cookies de sessão. Em cenários mais avançados, um Subdomain Takeover pode ser o primeiro elo em uma cadeia de ataque complexa, levando ao roubo de tokens de autenticação OAuth e, finalmente, ao comprometimento total de contas de usuários. Portanto, mesmo um takeover aparentemente menor nunca deve ser subestimado, pois pode fornecer a um invasor a base necessária para se aprofundar na infraestrutura de uma organização.

## Seção 2: A Base DNS do Subdomain Takeover

### 2.1 Uma Introdução aos Registros DNS Relevantes: A, CNAME, NS e MX

Para compreender a mecânica do Subdomain Takeover, é essencial entender a função de quatro tipos de registros DNS fundamentais. Esses registros são as instruções que guiam o tráfego na internet, e sua má configuração é a raiz da vulnerabilidade.

- **Registro A (Endereço)**: O tipo de registro mais básico, um registro A (ou AAAA para IPv6) mapeia um nome de host diretamente para um endereço IP. Por exemplo, ele diz aos navegadores que `www.exemplo.com` está localizado no endereço IP `93.184.216.34`.
- **Registro CNAME (Nome Canônico)**: Em vez de mapear para um endereço IP, um registro CNAME atua como um alias, apontando um nome de host para outro nome de host (o "nome canônico"). O resolvedor de DNS então realiza uma segunda busca para encontrar o endereço IP do nome canônico. Isso é comumente usado para apontar um subdomínio personalizado (por exemplo, `blog.empresa.com`) para um serviço de terceiros (por exemplo, `empresa.wordpress.com`).
- **Registro NS (Servidor de Nomes)**: Um registro NS delega a autoridade sobre uma zona DNS específica para um conjunto diferente de servidores de nomes. Por exemplo, os registros NS para `exemplo.com` podem apontar para os servidores de nomes do registrador de domínio, mas a organização pode criar registros NS para `sub.exemplo.com` para delegar o gerenciamento de todos os registros dentro desse subdomínio (como `api.sub.exemplo.com`) para um provedor de DNS em nuvem como o AWS Route 53.
- **Registro MX (Troca de Correio)**: Os registros MX especificam os servidores de correio responsáveis por aceitar mensagens de e-mail em nome de um domínio. Eles possuem um valor de prioridade para indicar a ordem de preferência, permitindo a configuração de servidores de backup.

### 2.2 Entendendo a Resolução e Delegação de DNS

O processo de resolução de DNS é uma série hierárquica de consultas que traduz um nome de domínio legível por humanos em um endereço IP legível por máquina. Quando um usuário digita `blog.exemplo.com`, o resolvedor local primeiro consulta os servidores raiz, depois os servidores de domínio de nível superior (TLD) para `.com` e, finalmente, os servidores de nomes autoritativos para `exemplo.com`.

É o conceito de delegação que é fundamental para os takeovers mais graves. Ao criar um registro NS para `sub.exemplo.com` apontando para os servidores de nomes da AWS, a zona `exemplo.com` efetivamente diz ao mundo: "Para qualquer consulta relacionada a `sub.exemplo.com` e qualquer coisa abaixo dele, não me pergunte; pergunte a esses servidores da AWS. Eu confio neles para fornecer a resposta autoritativa". Essa transferência de confiança é um pilar do design distribuído do DNS, mas também é o ponto de falha explorado em um NS Takeover.

A confiança é um elemento central que os invasores exploram, em vez de subverterem. Um resolvedor de DNS que segue um registro CNAME ou NS está funcionando exatamente como projetado. O protocolo em si não está quebrado. A falha ocorre quando o destino dessa confiança — seja o nome canônico em um registro CNAME ou os servidores de nomes em um registro NS — não é mais controlado pelo proprietário legítimo do domínio original. O invasor assume a propriedade do recurso de destino, e o DNS, seguindo suas regras, direciona legitimamente o tráfego para o invasor. A vulnerabilidade, portanto, não reside no protocolo DNS, mas nos processos organizacionais que gerenciam os endpoints para os quais os registros DNS apontam.

### 2.3 Como um Registro DNS se Torna "Pendente"

Um registro DNS se torna "pendente" ou "órfão" quando o elo entre o ponteiro (o registro DNS) e o recurso alvo é quebrado do lado do recurso, sem uma atualização correspondente do lado do DNS.

- **Cenário 1: Recurso de Nuvem Desprovisionado**: Este é o caso mais comum. Uma equipe de desenvolvimento cria uma aplicação web no Azure, recebendo o FQDN `minha-app-dev.azurewebsites.net`. Eles criam um registro CNAME em seu DNS corporativo, `dev.empresa.com`, para apontar para o FQDN do Azure. Meses depois, o projeto é concluído e a aplicação web do Azure é excluída para economizar custos. No entanto, ninguém na equipe de operações de TI ou de desenvolvimento remove o registro CNAME de `dev.empresa.com`. O registro agora aponta para um nome de host `azurewebsites.net` que não está mais registrado por ninguém, tornando-o disponível para ser reivindicado por qualquer outra conta do Azure.
- **Cenário 2: Domínio Expirado**: Uma empresa pode usar um serviço de terceiros para uma função específica, como e-mail marketing, e configurar um registro MX para `marketing.empresa.com` apontando para `servidor.provedor-email.net`. Se `provedor-email.net` for um domínio que a empresa registrou para esse fim e eles se esquecerem de renovar o registro do domínio, ele eventualmente expirará e se tornará disponível para compra pública. Um invasor pode então registrar `provedor-email.net`, configurar um servidor de e-mail e começar a receber e-mails destinados a `marketing.empresa.com`.

Ambos os cenários destacam uma falha fundamental no gerenciamento do ciclo de vida dos ativos: a falta de um processo coeso que vincule a existência de um registro DNS à existência do recurso para o qual ele aponta.

## Seção 3: Anatomia de uma Tomada de Controle: Vetores de Ataque Comuns e Avançados

O Subdomain Takeover pode se manifestar por meio de vários tipos de registros DNS. Embora o mecanismo central seja o mesmo — explorar um ponteiro pendente — o vetor de ataque e o impacto potencial variam significativamente dependendo do tipo de registro explorado.

### 3.1 Tomada de Controle de Registro CNAME: O Vetor Clássico

Esta é a forma mais prevalente de Subdomain Takeover, visando registros CNAME que apontam para serviços de terceiros onde os nomes de host podem ser reivindicados.

- **Mecanismo**: Um invasor identifica um subdomínio com um registro CNAME apontando para um serviço (por exemplo, `sub.empresa.com` CNAME `recurso-orfao.provedor.com`). O invasor então cria uma conta no `provedor.com` e reivindica o nome de host `recurso-orfao`. O serviço do provedor, agora vendo uma reivindicação válida, começa a servir o conteúdo do invasor em `sub.empresa.com`.
- **Exemplos Comuns**:
  - **AWS S3 e CloudFront**: Um CNAME aponta para um bucket S3 ou uma distribuição CloudFront que foi excluída. Um invasor pode simplesmente criar um novo bucket ou distribuição com o mesmo nome para assumir o controle. A resposta "The specified bucket does not exist" de um endpoint S3 é uma forte indicação de vulnerabilidade.
  - **Azure App Service e CDN**: Um CNAME aponta para um recurso `*.azurewebsites.net` ou `*.azureedge.net` que foi removido. Um invasor pode criar um novo App Service ou perfil de CDN com o nome correspondente para sequestrar o subdomínio.
  - **GitHub Pages**: Um CNAME aponta para uma página `usuario.github.io` onde o repositório ou a conta do usuário foi excluída. Um invasor pode registrar o nome de usuário ou criar um repositório para servir seu próprio conteúdo. A mensagem de erro "There isn't a GitHub Pages site here" é uma impressão digital clássica.

### 3.2 Tomada de Controle de Registro A: A Loteria de Endereços IP

Este vetor é mais complexo e muitas vezes mais oportunista do que direcionado. Ele ocorre quando o registro A de um subdomínio aponta para um endereço IP que foi desalocado de um pool de um provedor de nuvem, como um AWS Elastic IP (EIP).

- **Mecanismo 1 (Loteria/Força Bruta)**: Um invasor identifica um registro A pendente apontando para um IP específico dentro do intervalo de um provedor de nuvem. O invasor então executa um script que aloca e desaloca repetidamente endereços IP do provedor (por exemplo, EIPs da AWS) na esperança de que o provedor eventualmente reatribua o endereço IP alvo a ele. Este método é muitas vezes dificultado pela limitação de taxa e pelas medidas de detecção de abuso dos provedores de nuvem.
- **Mecanismo 2 (Tomada de Controle Passiva)**: Uma abordagem mais sofisticada e furtiva. Em vez de visar um IP específico, um invasor primeiro adquire um endereço IP de um provedor de nuvem. Em seguida, ele consulta bancos de dados de DNS passivo (pDNS) para ver se algum domínio ou subdomínio valioso já está apontando para o endereço IP que ele agora controla. Se uma correspondência for encontrada, ele pode explorar o takeover. Este método é oportunista e depende da sorte de ser atribuído um IP com um registro A pendente já existente.
- **Novos Vetores**: A introdução de recursos como a "transferência de Elastic IP" da AWS, que permite a transferência de um EIP entre contas da AWS, poderia, teoricamente, ser abusada se um invasor comprometesse uma conta da AWS, embora isso exija um acesso inicial significativo.

### 3.3 Tomada de Controle de Registro NS: Sequestrando a Zona Inteira

Considerado o tipo mais impactante de Subdomain Takeover, um NS Takeover concede ao invasor controle autoritativo sobre uma zona DNS inteira. Isso ocorre quando os registros NS de um subdomínio delegam autoridade a servidores de nomes que não estão mais sob o controle da organização.

- **Mecanismo**: Isso geralmente acontece de duas maneiras:
  - Os registros NS apontam para servidores de nomes em um domínio que expirou e foi registrado pelo invasor.
  - Os registros NS apontam para um serviço de DNS em nuvem (como Azure DNS ou AWS Route 53) onde a zona DNS correspondente foi excluída. O invasor então cria uma nova zona com o mesmo nome nesse serviço, reivindicando o controle.
- **Impacto**: Uma vez que o invasor controla os servidores de nomes autoritativos para a zona (por exemplo, `dev.empresa.com`), ele pode criar qualquer registro DNS dentro dessa zona. Isso inclui criar registros A para `api.dev.empresa.com`, registros MX para interceptar e-mails para `@dev.empresa.com`, e registros TXT para passar em desafios de verificação de domínio.
- **Estudo de Caso**: O incidente envolvendo `project-cascade.visualstudio.com` é um exemplo notório. Os registros NS para este subdomínio apontavam para zonas do Azure DNS que não estavam mais registradas. Pesquisadores de segurança conseguiram reivindicar a zona no Azure DNS, dando-lhes controle total sobre o subdomínio. Eles então encadearam essa vulnerabilidade para realizar um ataque de tomada de controle de conta do Azure DevOps em um clique.

### 3.4 Tomada de Controle de Registro MX: Interceptando o Fluxo de E-mails

Este vetor visa especificamente a infraestrutura de e-mail de uma organização, explorando registros MX que apontam para um servidor de e-mail em um domínio que não é mais controlado pela organização.

- **Mecanismo**: Um registro MX para `empresa.com` aponta para `mail.servico-terceirizado.com`. Se o domínio `servico-terceirizado.com` expirar ou for abandonado, um invasor pode registrá-lo. O invasor então configura seu próprio servidor de e-mail para aceitar e-mails destinados a `@empresa.com`. Como o registro MX legítimo agora aponta para um servidor controlado pelo invasor, os servidores de e-mail de envio começarão a entregar e-mails para o invasor.
- **Impacto**: O impacto é severo e direto. O invasor pode:
  - **Interceptar Comunicações Confidenciais**: Ler e-mails de negócios, comunicações de clientes e informações internas.
  - **Coletar Credenciais**: Interceptar e-mails de redefinição de senha para obter acesso a contas de funcionários ou clientes.
  - **Lançar Campanhas de Phishing**: Enviar e-mails de phishing altamente convincentes de um endereço de e-mail legítimo `@empresa.com`, aumentando drasticamente a taxa de sucesso.

**Tabela 3.1: Comparação de Vetores de Tomada de Controle de Registros DNS**

| **Tipo de Registro** | **Mecanismo Resumido** | **Alvos Comuns** | **Impacto Primário** | **Dificuldade/Probabilidade Relativa** |
| --- | --- | --- | --- | --- |
| **CNAME** | Aponta para um nome de serviço não reivindicado em uma plataforma de terceiros. | SaaS/PaaS (AWS S3, GitHub Pages, Azure App Service, Heroku, Shopify) | Hospedagem de conteúdo, XSS, roubo de cookies, phishing. | Alta |
| **A** | Aponta para um endereço IP desalocado de um pool de provedor de nuvem. | Máquinas Virtuais em Nuvem (AWS EC2, Azure VMs) | Hospedagem de conteúdo (geralmente oportunista), phishing. | Baixa a Média |
| **NS** | Delega uma zona DNS para servidores de nomes não reivindicados. | Serviços de DNS em Nuvem (Azure DNS, AWS Route 53), domínios de servidores de nomes expirados. | Controle total da zona (criação de qualquer tipo de registro), redirecionamento de tráfego, interceptação de e-mail. | Baixa, mas de Impacto Crítico |
| **MX** | Aponta para um servidor de e-mail em um domínio não reivindicado ou expirado. | Provedores de e-mail de terceiros, domínios de serviço de e-mail personalizados. | Interceptação e envio de e-mails, coleta de credenciais, phishing. | Média |

## Seção 4: O Efeito Dominó: Quantificando o Impacto de uma Tomada de Controle Bem-sucedida

A verdadeira gravidade de um Subdomain Takeover não reside apenas no controle inicial de um único subdomínio. Pelo contrário, sua severidade é determinada pelo "contexto de confiança" que o subdomínio comprometido possui dentro do ecossistema digital mais amplo da organização. Um subdomínio esquecido pode ser o ponto de partida para uma cascata de falhas de segurança, transformando uma misconfiguração de baixo risco em um incidente crítico.

### 4.1 Consequências Diretas: Danos à Reputação, Phishing e Distribuição de Malware

Os impactos imediatos de um takeover são frequentemente os mais visíveis e podem causar danos significativos por si só.

- **Desfiguração (Defacement)**: Um invasor pode substituir o conteúdo legítimo do subdomínio por mensagens ofensivas, propaganda política ou simplesmente um anúncio do hack. Embora tecnicamente simples, isso pode causar danos substanciais à reputação da marca e erodir a confiança do cliente.
- **Phishing e Coleta de Credenciais**: Este é um dos usos mais perigosos. Um invasor pode hospedar uma página de login falsa em um subdomínio confiável (por exemplo, `login.empresa.com`). Como o URL parece legítimo, os usuários são muito mais propensos a inserir suas credenciais. A situação é agravada pelo fato de que os gerenciadores de senhas podem preencher automaticamente as credenciais com base no domínio principal, entregando-as diretamente ao invasor com pouca ou nenhuma interação do usuário.
- **Distribuição de Malware**: Um subdomínio confiável pode ser usado para hospedar e distribuir malware. Isso pode contornar os filtros de reputação de segurança que, de outra forma, bloqueariam downloads de domínios maliciosos conhecidos. Os usuários são mais propensos a baixar e executar arquivos de um domínio que reconhecem e confiam.

### 4.2 Exploração Avançada: Encadeando Tomadas de Controle para um Comprometimento Mais Profundo

Um Subdomain Takeover raramente é o objetivo final de um invasor sofisticado; é um ponto de partida. A confiança implícita que uma organização deposita em seus próprios subdomínios pode ser explorada para contornar outras camadas de segurança.

- **Sequestro de Sessão via Roubo de Cookies**: Muitas aplicações web definem cookies de sessão com o escopo para o domínio pai (por exemplo, `Domain=.empresa.com`). Isso permite que o cookie seja enviado para qualquer subdomínio de `empresa.com`. Se um invasor controlar `sub.empresa.com`, qualquer usuário que visitar o site do invasor enviará seus cookies de sessão para o servidor do invasor. O invasor pode então usar esses cookies para sequestrar a sessão do usuário em outras aplicações legítimas, como o portal principal ou painéis de administração.
- **Contorno da Política de Segurança de Conteúdo (CSP) e da Falsificação de Solicitação entre Sites (CSRF)**: As políticas de segurança modernas frequentemente dependem de listas de permissões de origens confiáveis. É comum que uma aplicação em `www.empresa.com` confie em seus próprios subdomínios, incluindo-os em diretivas CSP como `script-src` ou `connect-src`. Se um invasor controlar um desses subdomínios na lista de permissões, ele pode hospedar scripts maliciosos que contornam a CSP e executam ataques de Cross-Site Scripting (XSS) no domínio principal. Da mesma forma, as defesas contra CSRF que dependem da verificação do cabeçalho `Origin` podem ser contornadas, pois a solicitação se originará de um subdomínio confiável.
- **Roubo de Tokens OAuth**: Este é um dos vetores de ataque mais críticos. Muitas aplicações que usam OAuth 2.0 para login de terceiros (por exemplo, "Entrar com o Google") configuram suas URIs de redirecionamento permitidas com um curinga (por exemplo, `https://*.empresa.com/oauth/callback`). Se um invasor assumir o controle de um subdomínio, ele pode usá-lo como uma URI de redirecionamento válida. O fluxo de ataque é o seguinte:
  - O invasor cria um link de login OAuth malicioso com o `redirect_uri` apontando para seu subdomínio sequestrado (por exemplo, `https://sub-sequestrado.empresa.com/callback`).
  - A vítima clica no link e se autentica com o provedor de OAuth.
  - O provedor de OAuth verifica que o `redirect_uri` corresponde ao padrão curinga permitido e redireciona a vítima de volta para o subdomínio do invasor, juntamente com o código de autorização ou token de acesso na URL.
  - O servidor do invasor captura o token, que pode então ser usado para acessar a conta da vítima na aplicação legítima.
  - O ataque de tomada de controle de conta do Azure DevOps demonstrou exatamente esse cenário na prática.

### 4.3 A Ameaça da Autoridade de Certificação: Abusando da Validação de Domínio

Um dos equívocos mais perigosos sobre o Subdomain Takeover é a crença de que um site protegido por HTTPS (indicado pelo cadeado no navegador) é imune. Na realidade, o oposto é verdadeiro: um invasor pode obter seu próprio certificado SSL/TLS válido para o subdomínio sequestrado, tornando seu ataque ainda mais convincente.

O processo de validação de domínio (DV) usado por Autoridades de Certificação (CAs) como a Let's Encrypt verifica se o solicitante controla o domínio para o qual está solicitando um certificado. Isso geralmente é feito de duas maneiras:

- **Desafio HTTP-01**: A CA solicita que o solicitante coloque um arquivo específico em um caminho conhecido no servidor web do domínio.
- **Desafio DNS-01**: A CA solicita que o solicitante crie um registro TXT específico no DNS do domínio.

Um invasor que executou um Subdomain Takeover pode passar facilmente em qualquer um desses desafios. Eles controlam o conteúdo servido no subdomínio (para o desafio HTTP) e, no caso de um NS Takeover, controlam os registros DNS (para o desafio DNS). Consequentemente, a CA emitirá um certificado SSL/TLS válido e confiável pelo navegador para o subdomínio do invasor. Isso significa que a página de phishing do invasor será servida por HTTPS, exibirá o cadeado de segurança e não acionará nenhum aviso do navegador, minando a confiança do usuário na segurança da web.

### 4.4 Ramificações Legais e Financeiras

O impacto de um Subdomain Takeover transcende as augustas consequências técnicas, estendendo-se a riscos financeiros e legais significativos.

- **Responsabilidade Regulatória**: Se um takeover levar a uma violação de dados envolvendo informações pessoais de cidadãos da UE, a organização pode enfrentar multas pesadas sob o Regulamento Geral sobre a Proteção de Dados (GDPR). O Artigo 82 do GDPR estipula o direito à compensação para indivíduos que sofreram danos materiais ou não materiais como resultado de uma infração, responsabilizando o controlador de dados. Falhas em manter a higiene adequada do DNS podem ser vistas como uma falha em implementar medidas de segurança técnica e organizacional apropriadas.
- **Quantificação do Impacto Financeiro**: Embora seja difícil atribuir um valor exato em dólares a um único takeover, o risco pode ser quantificado por meio de frameworks. O Subdomain/Domain Vulnerabilities Scoring System (SCSS), por exemplo, tenta classificar o risco com base em fatores como se o subdomínio é voltado para o cliente, sua idade e o tipo de vulnerabilidade, fornecendo uma pontuação para priorizar a remediação. Além disso, os custos indiretos incluem a resposta a incidentes, a notificação de clientes, a perda de negócios devido a danos à reputação e possíveis litígios.
- **Economia do Bug Bounty**: A prevalência e o impacto potencial dos Subdomain Takeovers são refletidos nos programas de bug bounty. Empresas frequentemente pagam recompensas significativas por relatórios válidos, com os valores variando com base no impacto contextual do subdomínio. Um takeover em um subdomínio que permite o roubo de cookies de sessão ou o comprometimento de contas OAuth receberá uma recompensa muito maior do que um em um site de marketing estático desativado.

## Seção 5: A Caçada: Uma Abordagem Metódica para Detecção e Verificação

A identificação de vulnerabilidades de Subdomain Takeover requer uma abordagem sistemática que combina reconhecimento passivo, verificação ativa e automação em escala. O processo visa primeiro descobrir todos os subdomínios de uma organização e, em seguida, testar cada um em busca de sinais de ponteiros DNS pendentes.

### 5.1 Reconhecimento: Descobrindo a Superfície de Ataque

O primeiro passo em qualquer caçada de takeover é construir um inventário abrangente de subdomínios. Sem uma lista completa, pontos de entrada vulneráveis podem facilmente passar despercebidos.

- **Técnicas Passivas**: Esses métodos coletam informações de fontes de terceiros sem enviar pacotes diretamente para a infraestrutura do alvo, tornando-os furtivos e não intrusivos. A técnica passiva mais poderosa na era moderna é a mineração de Logs de Transparência de Certificados (CT). Os CT logs são registros públicos e auditáveis de todos os certificados SSL/TLS emitidos por Autoridades de Certificação. A análise desses logs pode revelar subdomínios, incluindo aqueles usados para fins internos ou de teste, que podem não ser detectáveis por outros meios. Ferramentas como `crt.sh` permitem que pesquisadores consultem esses logs para qualquer domínio. Outras fontes passivas incluem mecanismos de busca, arquivos da web e plataformas de inteligência de ameaças.
- **Técnicas Ativas**: Esses métodos interagem diretamente com a infraestrutura DNS do alvo. A técnica mais comum é a força bruta de DNS, que usa listas de palavras de nomes de subdomínios comuns (por exemplo, `www`, `api`, `dev`, `blog`) e tenta resolver cada um deles para o domínio alvo (por exemplo, `api.empresa.com`). Ferramentas como `dnsgen` podem gerar permutações e alterações de subdomínios conhecidos para descobrir novos.

### 5.2 Identificando Ponteiros Pendentes e Impressões Digitais de Serviços

Com uma lista de subdomínios em mãos, a próxima fase é analisar cada um em busca de evidências de que ele aponta para um recurso não reivindicado.

- **Verificação Manual**: Ferramentas de linha de comando como `dig` e `nslookup` são essenciais para a verificação manual. Um pesquisador usará essas ferramentas para consultar os registros CNAME, A, NS e MX de um subdomínio. Um sinal revelador é quando a resolução do DNS tem sucesso (ou seja, o registro CNAME existe), mas uma solicitação HTTP subsequente para o subdomínio retorna uma página de erro "404 Not Found" que é distinta e característica de um serviço em nuvem específico. Por exemplo, o GitHub exibe uma página com a mensagem "There isn't a GitHub Pages site here", que é uma impressão digital inequívoca de um potencial takeover. Um status de resposta `NXDOMAIN` (Non-Existent Domain) para o alvo de um CNAME também é um forte indicador.
- **Impressões Digitais de Serviço (Fingerprints)**: Cada serviço em nuvem vulnerável tem um conjunto único de "impressões digitais" que indicam um recurso não reivindicado. Uma impressão digital é tipicamente uma combinação de:
  - O padrão do nome de host no registro CNAME (por exemplo, `*.s3.amazonaws.com`, `*.azurewebsites.net`).
  - O conteúdo específico no corpo da resposta HTTP (por exemplo, "The specified bucket does not exist").
  - Cabeçalhos de resposta específicos.
  - O código de status HTTP retornado (geralmente 404).

### 5.3 Varredura Automatizada: Aproveitando Ferramentas para Detecção em Escala

A verificação manual é impraticável para organizações com centenas ou milhares de subdomínios. A automação é, portanto, crucial tanto para invasores quanto para defensores.

- **Visão Geral das Ferramentas**: Uma variedade de ferramentas de código aberto foi desenvolvida para automatizar a detecção de Subdomain Takeover. Ferramentas populares incluem `subjack`, `tko-subs`, `subzy` e, mais proeminentemente, `nuclei`.
- **Como Funcionam**: Essas ferramentas operam com um princípio simples: elas pegam uma lista de subdomínios como entrada e, para cada um, resolvem seu registro CNAME (ou verificam sua resposta HTTP). Elas então comparam o resultado com um banco de dados interno de impressões digitais de serviços vulneráveis conhecidos. Esses bancos de dados são geralmente mantidos como arquivos de configuração, como o `fingerprints.json` usado pelo `subjack`.
- **Templates do Nuclei**: O `Nuclei` se destaca por sua flexibilidade. Em vez de um banco de dados codificado, ele usa templates baseados em YAML que definem a lógica de detecção para vulnerabilidades específicas, incluindo takeovers. Um template de takeover do `Nuclei` especificará o tipo de consulta a ser feita (por exemplo, DNS, HTTP), os padrões a serem procurados nos registros CNAME e as palavras-chave ou expressões regulares a serem correspondidas no corpo ou nos cabeçalhos da resposta. Isso torna o `Nuclei` altamente extensível e permite que a comunidade de segurança adicione rapidamente detecções para novos serviços vulneráveis.

**Tabela 5.1: Serviços em Nuvem Vulneráveis e Suas Impressões Digitais**

| **Provedor de Serviço** | **Padrão CNAME** | **Impressão Digital (Corpo da Resposta/Cabeçalho)** | **Código de Status/DNS** |
| --- | --- | --- | --- |
| **AWS S3** | `s3.amazonaws.com` | The specified bucket does not exist | 404 |
| **AWS Elastic Beanstalk** | `elasticbeanstalk.com` | N/A (a resolução falha) | NXDOMAIN |
| **AWS CloudFront** | `cloudfront.net` | ERROR: The request could not be satisfied | 404/403 |
| **Azure App Service** | `azurewebsites.net` | Error 404 - Web app not found. | 404 |
| **Azure CDN** | `azureedge.net` | The resource you are looking for has been removed... | 404 |
| **Azure Traffic Manager** | `trafficmanager.net` | N/A (a resolução falha) | NXDOMAIN |
| **GitHub Pages** | `github.io` | There isn't a GitHub Pages site here. | 404 |
| **Heroku** | `herokuapp.com` | No such app | 404 |
| **Shopify** | `myshopify.com` | Sorry, this shop is currently unavailable. | 404 |
| **Zendesk** | `zendesk.com` | Help Center Closed | 404 |

## Seção 6: Construindo uma Defesa Resiliente: Prevenção e Mitigação em Múltiplas Camadas

A defesa eficaz contra o Subdomain Takeover não depende de uma única tecnologia, mas de uma abordagem em camadas que combina higiene de processos robusta, controles técnicos nativos da nuvem e automação. A vulnerabilidade é fundamentalmente um problema de processo, e, portanto, a solução mais duradoura também deve ser orientada por processos.

### 6.1 Higiene Fundamental de DNS: Processo e Governança

A defesa mais crítica e fundamental contra o Subdomain Takeover é a implementação de processos rigorosos de gerenciamento do ciclo de vida de ativos.

- **A "Ordem das Operações"**: A regra de ouro para prevenir registros pendentes é garantir que as operações de DNS e de recursos sejam executadas na sequência correta:
  - **Provisionamento**: Sempre reivindique ou crie o recurso na plataforma de terceiros primeiro. Somente depois que o recurso estiver ativo e sob seu controle, crie o registro DNS para apontar para ele.
  - **Desprovisionamento**: Sempre exclua o registro DNS primeiro. Depois que o registro for removido e a alteração for propagada, desative ou exclua o recurso na plataforma de terceiros. Esta abordagem de "cortar a energia no disjuntor" garante que nunca haja um período em que um registro DNS ativo aponte para um recurso não reivindicado.
- **Auditoria Contínua**: As organizações devem realizar auditorias regulares e automatizadas de todas as suas zonas DNS para identificar e remover registros obsoletos. Isso não deve ser um exercício pontual, mas um processo contínuo para manter a higiene do DNS.

### 6.2 Defesas Nativas da Nuvem: Uma Análise Comparativa de Registros Alias

Reconhecendo a prevalência de registros pendentes, os principais provedores de nuvem introduziram tipos de registros DNS proprietários que ajudam a mitigar o problema na origem. Esses registros, conhecidos como "Registros Alias", acoplam o ciclo de vida de um registro DNS ao ciclo de vida de um recurso de nuvem específico.

- **Registros Alias do Azure DNS**: O Azure DNS permite a criação de registros Alias que apontam para recursos específicos do Azure, como Endereços IP Públicos, perfis do Gerenciador de Tráfego ou endpoints da Porta da Frente do Azure. A principal vantagem é que, se o recurso subjacente for excluído, o registro Alias do DNS se torna automaticamente um conjunto de registros vazio. Ele para de resolver, em vez de apontar para um recurso que não existe mais, eliminando assim a condição de pendência.
- **Registros Alias do AWS Route 53**: O Route 53 da AWS oferece uma funcionalidade semelhante. Os registros Alias podem apontar para recursos da AWS como balanceadores de carga elásticos (ELBs), distribuições do CloudFront ou buckets S3. Quando o recurso alvo é excluído, o Route 53 detecta isso e para de responder às consultas para aquele registro Alias, retornando uma resposta `NXDOMAIN` ou vazia. Isso impede que o registro se torne pendente e vulnerável a um takeover.
- **Comparação com CNAMEs**: Para recursos hospedados dentro do mesmo provedor de nuvem, os registros Alias são inerentemente mais seguros do que os registros CNAME. Um CNAME é um simples ponteiro para outro nome de domínio; o sistema DNS não tem conhecimento do ciclo de vida do recurso por trás desse nome. Em contraste, um registro Alias é uma construção em nível de provedor que está ciente do recurso alvo, permitindo que o sistema DNS reaja à sua exclusão.

### 6.3 Salvaguardas Processuais: Verificação de Propriedade e Controles de Registrador

Além dos controles técnicos, salvaguardas processuais podem adicionar camadas adicionais de defesa.

- **Verificação de Propriedade de Domínio**: Muitos serviços SaaS agora exigem que os usuários provem o controle de um domínio antes de permitir que ele seja mapeado para seus serviços. Isso geralmente é feito exigindo que o usuário crie um registro TXT exclusivo em seu DNS. Um invasor que descobre um CNAME pendente não será capaz de reivindicar o serviço se não puder criar o registro TXT necessário no DNS da vítima. Este mecanismo impede efetivamente que um invasor reivindique um subdomínio que não possui.
- **Controles em Nível de Registrador**: A segurança fundamental do domínio começa no registrador. As organizações devem usar recursos como o Bloqueio de Registrador de Domínio para impedir transferências ou modificações não autorizadas nos registros NS ou outros registros críticos. Além disso, a habilitação da Autenticação Multifator (MFA) em todas as contas de gerenciamento de DNS e de registradores é uma prática de segurança essencial para prevenir o acesso não autorizado.

### 6.4 Automação com Infraestrutura como Código (IaC)

A abordagem mais robusta e escalável para prevenir Subdomain Takeovers é codificar a relação entre os recursos da nuvem e os registros DNS usando ferramentas de Infraestrutura como Código (IaC), como o Terraform.

Ao definir tanto um recurso de nuvem (por exemplo, um bucket S3 da AWS) quanto seu registro DNS correspondente (por exemplo, um registro Alias do Route 53) no mesmo arquivo de configuração do Terraform, seus ciclos de vida se tornam programaticamente acoplados. Quando um engenheiro executa `terraform apply`, tanto o recurso quanto o registro DNS são criados. Mais importante, quando `terraform destroy` é executado, o Terraform gerencia a ordem de destruição, garantindo que o registro DNS seja removido antes ou simultaneamente com o recurso. Isso transforma a prevenção de uma questão de adesão manual a um processo para uma aplicação automatizada e confiável, reduzindo drasticamente o risco de erro humano.

**Tabela 6.1: Estratégias de Mitigação de Provedores de Nuvem**

| **Provedor de Nuvem** | **Recurso Recomendado** | **Mecanismo** | **Método de Verificação de Propriedade** | **Recursos Aplicáveis** |
| --- | --- | --- | --- | --- |
| **AWS** | Registro Alias do Route 53 | Acopla o ciclo de vida do registro DNS ao do recurso AWS. Para de resolver quando o recurso é excluído. | N/A para Alias | ELB, CloudFront, S3, API Gateway, etc. |
| **Azure** | Registro Alias do Azure DNS | Acopla o ciclo de vida do registro DNS ao do recurso Azure. Torna-se um conjunto de registros vazio quando o recurso é excluído. | Registro TXT asuid para App Service | Endereço IP Público, Gerenciador de Tráfego, Porta da Frente, CDN |
| **GCP** | N/A (Usa CNAMEs) | N/A | Verificação de propriedade baseada em TXT para serviços como App Engine. | App Engine, Cloud Storage, etc. |

## Seção 7: Abordando a Causa Raiz: Uma Perspectiva Organizacional

Embora as mitigações técnicas sejam essenciais, elas tratam os sintomas de um problema mais profundo. A prevalência persistente de registros DNS pendentes em grandes empresas é um forte indicador de disfunção organizacional e de uma falha em adaptar os processos de governança à era da nuvem. Um registro DNS pendente pode ser visto como um "canário na mina de carvão", sinalizando problemas mais amplos na postura de governança e segurança na nuvem de uma empresa. Se uma organização não consegue rastrear e gerenciar o ciclo de vida de seus subdomínios, é provável que também tenha dificuldades em gerenciar outros ativos efêmeros na nuvem, como buckets de armazenamento, máquinas virtuais e funções de gerenciamento de identidade e acesso.

### 7.1 Analisando as Falhas de Processo que Levam ao DNS Pendente

A causa raiz do DNS pendente raramente é uma única falha técnica, mas sim uma cascata de falhas de processo. Essas falhas são frequentemente sintomas de disfunção organizacional mais ampla, onde os sistemas e fluxos de trabalho não estão alinhados com as realidades operacionais.

As principais falhas de processo incluem:

- **Falta de um Inventário de Ativos Centralizado**: Muitas grandes organizações não possuem um inventário único, preciso e atualizado de todos os seus domínios, subdomínios e os recursos de nuvem associados. Sem visibilidade, o gerenciamento é impossível.
- **Procedimentos de Descomissionamento Inexistentes ou Não Aplicados**: As equipes podem ter processos bem definidos para provisionar novos recursos, mas carecem de um procedimento igualmente rigoroso para o descomissionamento. A etapa de "limpar registros DNS" é frequentemente omitida ou esquecida.
- **Silos de Comunicação**: Em muitas empresas, a equipe que gerencia o DNS (geralmente TI central ou operações de rede) é diferente da equipe que gerencia os recursos de nuvem (geralmente equipes de desenvolvimento ou DevOps). Quando uma equipe de desenvolvimento desativa um serviço, a comunicação necessária para a equipe de DNS remover o registro correspondente muitas vezes não ocorre.

### 7.2 Estabelecendo Propriedade e Governança Claras em Empresas Complexas

A solução para a disfunção organizacional é estabelecer linhas claras de responsabilidade e governança. Cada ativo digital, incluindo cada registro DNS, deve ter um proprietário designado que seja responsável por todo o seu ciclo de vida.

Isso é particularmente desafiador em grandes empresas, onde o gerenciamento de domínios pode envolver dezenas de fornecedores (registradores, provedores de DNS gerenciado) e partes interessadas internas (Marketing, Jurídico, P&D). Um modelo de governança centralizado é necessário para impor políticas consistentes. Isso deve incluir:

- **Controles de Acesso Estritos**: O acesso para modificar registros DNS deve ser rigorosamente controlado e limitado a pessoal autorizado, seguindo o princípio do menor privilégio.
- **Políticas Claras de Gerenciamento de Domínio**: A organização deve ter políticas documentadas e aplicadas para o registro, uso e desativação de domínios e subdomínios.

### 7.3 Integrando a Segurança no Ciclo de Vida do DevOps

Em vez de depender de auditorias periódicas e limpezas manuais reativas, a segurança do DNS deve ser integrada ao ciclo de vida de desenvolvimento de software ("shift-left").

- **Automação via IaC**: Como discutido anteriormente, usar ferramentas como o Terraform para gerenciar tanto a infraestrutura quanto o DNS como código é a maneira mais eficaz de impor a higiene do ciclo de vida.
- **Varredura Automatizada em Pipelines de CI/CD**: As ferramentas de varredura de segurança devem ser integradas aos pipelines de CI/CD para verificar a existência de registros DNS pendentes antes das implantações e para garantir que os processos de limpeza sejam executados corretamente durante o descomissionamento.

Tratar a descoberta de um registro DNS pendente não apenas como uma vulnerabilidade a ser corrigida, mas como um impulso para auditar todo o programa de gerenciamento de ativos na nuvem, é a mudança de uma postura de segurança reativa para uma proativa. Corrigir o subdomínio é tratar o sintoma; corrigir o processo é curar a doença.

## Seção 8: Conclusão: O Cenário em Evolução e a Perspectiva Futura

### 8.1 Resumo das Principais Ameaças e Defesas

O Subdomain Takeover continua sendo uma vulnerabilidade persistente e de alto impacto, enraizada em falhas de processo de gerenciamento de ciclo de vida de ativos, em vez de falhas de protocolo. Os vetores de ataque mais comuns exploram registros CNAME pendentes, enquanto os mais perigosos visam registros NS para obter controle total da zona. O impacto de um takeover bem-sucedido vai muito além da simples desfiguração, servindo como um ponto de partida para ataques em cadeia que podem levar ao roubo de cookies de sessão, bypass de políticas de segurança e comprometimento total de contas por meio do roubo de tokens OAuth.

As defesas mais eficazes são multicamadas, combinando higiene de processo fundamental (a "ordem das operações"), controles técnicos nativos da nuvem (registros Alias) e automação robusta por meio de Infraestrutura como Código. A prevenção, em vez da detecção reativa, é a estratégia mais resiliente.

### 8.2 Vetores Emergentes: Serverless, API Gateways e a Próxima Fronteira

O cenário de ameaças de Subdomain Takeover está em constante evolução, acompanhando as tendências da tecnologia em nuvem. Embora os vetores clássicos permaneçam relevantes, novas superfícies de ataque estão surgindo à medida que as arquiteturas de aplicação mudam.

- **Serverless e API Gateways**: A crescente adoção de arquiteturas serverless e serviços como o AWS API Gateway introduz novos vetores potenciais. Esses serviços geralmente permitem que os usuários mapeiem domínios personalizados para seus endpoints de API ou funções. Se uma API é implantada, um domínio personalizado é mapeado para ela e, posteriormente, a API é excluída sem remover o registro DNS, um takeover se torna possível. Um invasor poderia registrar uma nova API Gateway e reivindicar o mesmo endpoint, sequestrando o tráfego da API.
- **Evolução da Misconfiguração**: A pesquisa de 2024 e as projeções para 2025 indicam que, embora os mecanismos de takeover permaneçam os mesmos, a velocidade e a escala dos ataques estão aumentando. Ferramentas de automação como o `Nuclei` tornam mais fácil para os invasores escanear a internet em busca de vulnerabilidades em escala. A tendência de "esquecer ativos" só se intensificará à medida que mais serviços de nicho e plataformas SaaS forem adotados e posteriormente abandonados, criando um campo fértil para registros pendentes.

### 8.3 Recomendações Finais para uma Postura de Segurança Proativa

O Subdomain Takeover é, em grande parte, um problema solucionado do ponto de vista técnico, mas que persiste devido a falhas organizacionais e de processo. Para construir uma defesa duradoura, as organizações devem adotar uma filosofia de segurança proativa centrada em três pilares: **Auditar**, **Automatizar** e **Governar**.

- **Auditar**: Manter um inventário contínuo, completo e preciso de todos os ativos de DNS e dos recursos de nuvem associados. A visibilidade é o pré-requisito para o controle. Ferramentas de Gerenciamento de Superfície de Ataque Externa (EASM) e monitoramento de logs de Transparência de Certificados são cruciais para essa tarefa.
- **Automatizar**: Remover o erro humano da equação sempre que possível. Usar Infraestrutura como Código para gerenciar o ciclo de vida de DNS e recursos de forma coesa. Empregar recursos nativos da nuvem, como Registros Alias, para acoplar programaticamente os ciclos de vida.
- **Governar**: Estabelecer propriedade clara para cada ativo digital. Implementar e aplicar políticas rigorosas de provisionamento e descomissionamento. Quebrar os silos de comunicação entre as equipes de desenvolvimento, operações e segurança para garantir que a higiene do DNS seja uma responsabilidade compartilhada.

A ameaça do Subdomain Takeover não está diminuindo. Pelo contrário, a crescente complexidade e velocidade dos ambientes de nuvem modernos garantem que ela permanecerá uma preocupação relevante. As organizações que não conseguirem adaptar seus processos de governança e segurança para acompanhar seu ritmo de desenvolvimento continuarão a ser vulneráveis a essa forma de ataque evitável, mas potencialmente devastadora.