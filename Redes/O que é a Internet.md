# Um Relatório Abrangente sobre a Arquitetura, Operação e Evolução da Internet

## 1.1 O que é a Internet?

A Internet é um sistema global de redes de computadores interligadas que utiliza o conjunto de protocolos TCP/IP para se comunicar.1 No entanto, esta definição técnica, embora precisa, apenas arranha a superfície de um dos sistemas de engenharia mais complexos e transformadores já criados pela humanidade. Para uma compreensão aprofundada, a Internet deve ser analisada através de duas lentes complementares: a dos seus componentes constituintes e a dos serviços que ela habilita.

### 1.1.1 Uma descrição dos componentes da rede

Do ponto de vista dos componentes, a Internet é uma infraestrutura vasta e tangível. É um conjunto de hardware e software que fornece a base para a conectividade global. Os componentes físicos incluem bilhões de dispositivos de computação conectados, conhecidos como sistemas finais ou hosts, que vão desde computadores pessoais (PCs) e servidores em data centers até smartphones e dispositivos da Internet das Coisas (IoT).2 Esses dispositivos são interligados por uma teia de enlaces de comunicação e comutadores de pacotes.3

Os enlaces de comunicação são os meios físicos que transportam os dados. Eles são compostos por uma variedade de tecnologias, como cabos de cobre, fibra óptica e o espectro de rádio para comunicações sem fio.4 Os comutadores de pacotes, principalmente roteadores e comutadores (switches) de Camada de Enlace, são dispositivos especializados cuja função é receber os dados que chegam por um enlace de comunicação e encaminhá-los para o próximo enlace no caminho até o seu destino final.5

A razão pela qual esta coleção massiva e heterogênea de hardware, proveniente de inúmeros fabricantes e executando sistemas operacionais distintos, pode se comunicar de forma coesa reside nos componentes lógicos: os protocolos.6 A adesão a protocolos padronizados, notavelmente o conjunto de protocolos TCP/IP, fornece a uniformidade necessária sobre uma base de hardware diversa, garantindo a interoperabilidade que define a Internet.1

### 1.1.2 Uma descrição do serviço

Do ponto de vista dos serviços, a Internet é uma infraestrutura que fornece uma plataforma para aplicações distribuídas.8 Esta é a perspectiva do usuário, que responde à pergunta: "Para que serve a Internet?". Esses serviços são a razão de ser da rede para a vasta maioria de seus usuários e incluem uma gama extraordinariamente ampla de funcionalidades, como a World Wide Web (WWW), correio eletrônico (e-mail), streaming de vídeo e áudio, mensagens instantâneas, telefonia por IP (VoIP), jogos online e comércio eletrônico.1

A maioria desses serviços opera sob o modelo cliente-servidor. Neste modelo, um programa cliente, executado no sistema final do usuário (por exemplo, um navegador web ou um aplicativo de e-mail), solicita e recebe serviços de um programa servidor, que está sempre ativo e em execução em um data center.11 Por exemplo, quando se acessa um site, o navegador (cliente) envia uma solicitação a um servidor web, que responde enviando os arquivos da página solicitada de volta para o navegador.9

A arquitetura da Internet foi projetada para fornecer um serviço de transporte de dados genérico, sem ser otimizada para uma aplicação específica. Esta separação entre a infraestrutura de rede e as aplicações que nela rodam é um dos seus traços mais geniais.13 Ela permite a chamada "inovação sem permissão": qualquer pessoa com uma conexão à Internet pode criar e implantar um novo serviço ou aplicação sem precisar da aprovação dos proprietários da infraestrutura de rede (como os Provedores de Serviços de Internet, ou ISPs). Foi essa filosofia de design que permitiu a explosão de inovação que vimos com o surgimento de serviços como YouTube, Facebook e WhatsApp, que não foram previstos pelos arquitetos originais da rede.

### 1.1.3 O que é um protocolo?

Um protocolo é um conjunto formal de regras e convenções que governam a troca de informações entre dois ou mais sistemas computacionais.14 Se a Internet é uma conversa global entre dispositivos, os protocolos são a linguagem e a gramática que tornam essa conversa possível.16 Sem protocolos, os computadores não saberiam como iniciar uma comunicação, formatar os dados, interpretar as mensagens recebidas ou lidar com erros, resultando em caos e na impossibilidade de comunicação.17 Eles funcionam como uma linguagem universal que permite a interoperabilidade entre hardware e software de diferentes fabricantes.14

Todo protocolo de comunicação é definido por três elementos-chave 18:

- **Sintaxe**: Refere-se à estrutura ou formato dos dados, especificando a ordem em que são apresentados. Por exemplo, a sintaxe de um protocolo define quais campos compõem o cabeçalho de uma mensagem e o tamanho de cada campo.
- **Semântica**: Refere-se ao significado de cada seção de bits. Ela interpreta o propósito de cada campo sintático, dando sentido à mensagem. Por exemplo, a semântica define que um campo específico no cabeçalho representa o endereço do destinatário.
- **Timing**: Refere-se a quando os dados devem ser enviados e com que velocidade. Inclui a sincronização da comunicação, o controle de fluxo (para não sobrecarregar o receptor) e o estabelecimento e encerramento de conexões.

Os protocolos são o "DNA" da rede, pois suas regras de design ditam o comportamento e as características fundamentais da Internet. Por exemplo, o Protocolo de Internet (IP), a espinha dorsal da rede, foi projetado para oferecer um serviço "não confiável" e de "melhor esforço" (best-effort).20 Isso significa que o IP não garante que um pacote de dados chegará ao seu destino, nem que chegará em ordem. Esta decisão de design, codificada no protocolo, simplifica enormemente o trabalho dos roteadores no núcleo da rede, tornando-a mais escalável e resiliente. No entanto, ela transfere a responsabilidade de garantir a entrega confiável para os sistemas finais na periferia da rede, que utilizam um protocolo de camada superior, o Protocolo de Controle de Transmissão (TCP), para essa finalidade. Assim, as características fundamentais da Internet são uma consequência direta das regras definidas em seus protocolos.

## 1.2 A periferia da Internet

A periferia da Internet, também conhecida como a "borda" da rede, é onde os usuários e seus dispositivos se conectam à infraestrutura global. É composta pelas redes de acesso e pelos meios físicos que constituem a "última milha" da comunicação.

### 1.2.1 Redes de acesso

As redes de acesso são as tecnologias que conectam os sistemas finais (como residências, empresas e dispositivos móveis) ao primeiro roteador no caminho para o núcleo da Internet. A escolha da tecnologia de acesso é um compromisso entre velocidade, custo, disponibilidade e confiabilidade.21 As principais categorias de redes de acesso são:

**Acesso Residencial e Empresarial**: As redes de acesso podem ser divididas em dois grandes mercados: residencial e empresarial. A internet residencial é projetada para atividades como navegação, streaming e jogos, geralmente com velocidades de upload menores que as de download (assimétricas).23 A internet empresarial, por outro lado, é voltada para operações críticas, oferecendo maior confiabilidade, velocidades simétricas, suporte técnico prioritário garantido por um Acordo de Nível de Serviço (SLA) e, frequentemente, um endereço IP fixo, que é essencial para hospedar servidores ou sistemas de acesso remoto.23

**Tecnologias de Acesso**:

- **Digital Subscriber Line (DSL)**: Utiliza a infraestrutura de linhas telefônicas de cobre existentes para transmitir dados digitais. A velocidade diminui com a distância da central telefônica.27
- **Cabo**: Utiliza a rede de cabos coaxiais da TV a cabo. É uma rede de meio compartilhado, o que significa que a largura de banda é dividida entre os usuários de uma mesma vizinhança.28
- **Fibra Óptica (FTTH - Fiber to the Home)**: Transmite dados como pulsos de luz através de finíssimos fios de vidro. Oferece as maiores velocidades e a maior confiabilidade, sendo menos suscetível a interferências.23
- **Redes Móveis (4G/5G)**: Utilizadas tanto para acesso móvel (smartphones) quanto para acesso sem fio fixo (Fixed Wireless Access - FWA), onde um roteador em casa se conecta a uma torre de celular 5G.27
- **Satélite**: Fornece acesso em áreas remotas onde as tecnologias terrestres não estão disponíveis, mas geralmente possui maior latência devido à grande distância que os sinais precisam percorrer.29
- **Wi-Fi**: É importante notar que o Wi-Fi não é uma tecnologia de acesso à Internet, mas sim uma tecnologia de rede local sem fio (WLAN). Ele distribui uma conexão de acesso existente (seja ela fibra, cabo ou FWA) dentro de um espaço limitado, como uma casa ou escritório.31

A tabela a seguir compara as principais tecnologias de acesso à Internet.

**Tabela 1: Comparativo de Tecnologias de Acesso à Internet**

| Característica | DSL (Digital Subscriber Line) | Cabo (HFC) | Fibra Óptica (FTTH) | 5G FWA (Fixed Wireless Access) | Satélite |
|----------------|-------------------------------|------------|----------------------|--------------------------------|----------|
| **Meio Físico** | Par de cobre (linha telefônica) | Cabo Coaxial e Fibra | Fibra de vidro | Ondas de rádio | Ondas de rádio |
| **Velocidade Típica** | Baixa a Média (assimétrica) | Média a Alta (assimétrica) | Muito Alta (frequentemente simétrica) | Alta a Muito Alta (assimétrica) | Baixa a Média (assimétrica) |
| **Latência** | Média | Baixa a Média | Muito Baixa | Baixa | Muito Alta |
| **Confiabilidade** | Média | Média a Alta | Muito Alta | Média | Baixa a Média |
| **Vantagens** | Ampla disponibilidade usando linhas telefônicas existentes. | Velocidades mais altas que DSL, amplamente disponível. | Velocidade e confiabilidade superiores, imune a interferência eletromagnética. | Instalação rápida sem cabos, alta velocidade potencial. | Cobertura quase global, ideal para áreas rurais. |
| **Desvantagens** | Velocidade depende da distância da central. | Largura de banda compartilhada pode causar lentidão em horários de pico. | Custo de implantação elevado, disponibilidade limitada. | Suscetível a interferências e obstruções físicas; desempenho pode variar. | Alta latência, suscetível a condições climáticas, limites de dados. |

*Fontes: 22*

### 1.2.2 Meios físicos

Os bits que compõem os dados digitais viajam de um sistema a outro como sinais através de um meio físico. Cada bit é propagado por meio de ondas eletromagnéticas ou pulsos ópticos.36 Esses meios podem ser classificados em guiados e não guiados.

**Meios Guiados**: Os sinais se propagam de forma confinada ao longo de um meio sólido.

- **Par Trançado**: Consiste em pares de fios de cobre trançados para reduzir a interferência eletromagnética de fontes externas e a diafonia (crosstalk) entre pares adjacentes.36 É o meio mais comum em redes locais (LANs), usando conectores como o RJ45.37
- **Cabo Coaxial**: Consiste em um condutor de cobre central, cercado por um material isolante, uma malha condutora e uma cobertura externa. Oferece melhor blindagem e maior largura de banda que o par trançado.4
- **Fibra Óptica**: Transmite dados como pulsos de luz através de um filamento de vidro ou plástico extremamente fino. É imune à interferência eletromagnética, suporta taxas de transmissão altíssimas (Gbps a Tbps) e pode cobrir longas distâncias com baixa perda de sinal.36 É o meio preferido para os backbones da Internet.

**Meios Não Guiados (Sem Fio)**: Os sinais se propagam livremente pelo espaço.

- **Espectro de Rádio**: As comunicações sem fio utilizam diferentes faixas do espectro de rádio para transmitir informações.38 O espectro é um recurso público, finito e regulamentado por agências governamentais para evitar interferências.39 Ondas de rádio são usadas em tecnologias como Wi-Fi, redes celulares (4G/5G) e Bluetooth.40
- **Infravermelho**: Utiliza ondas infravermelhas para comunicação de curta distância e em linha de visada, como em controles remotos.36

A escolha do meio físico impõe limites fundamentais ao desempenho da rede. A velocidade da luz, por exemplo, estabelece um limite mínimo para o atraso de propagação, independentemente da sofisticação dos protocolos utilizados.43 A física da transmissão de sinais é, portanto, uma base inescapável sobre a qual toda a arquitetura da Internet é construída.

## 1.3 O núcleo da rede

Enquanto a periferia da Internet é onde as aplicações vivem e os usuários se conectam, o núcleo da rede é uma malha de roteadores interconectados responsável por uma única e crucial tarefa: mover pacotes de dados da origem ao destino da forma mais eficiente e robusta possível. O funcionamento do núcleo é definido por seu método de comutação e por sua estrutura como uma "rede de redes".

### 1.3.1 Comutação de pacotes

A Internet é uma rede de comutação de pacotes.44 Em vez de dedicar um caminho de ponta a ponta para uma comunicação, este método divide as mensagens longas (como um e-mail ou um arquivo de vídeo) em blocos de dados menores e de tamanho gerenciável chamados pacotes.18 Cada pacote é tratado de forma independente. Ele contém não apenas uma porção dos dados originais (a carga útil ou payload), mas também um cabeçalho com informações de controle essenciais, como os endereços IP do remetente e do destinatário.18

Os pacotes são então enviados para a rede. No núcleo, os roteadores utilizam o endereço de destino no cabeçalho de cada pacote para decidir para qual de seus enlaces de saída devem encaminhá-lo. Esse processo de encaminhamento é baseado no mecanismo de store-and-forward (armazenar e reenviar).47 Isso significa que um roteador deve receber e armazenar o pacote inteiro em sua memória (buffer) antes de poder iniciar sua transmissão para o próximo roteador no caminho.3 Esse mecanismo garante que o roteador possa verificar a integridade do pacote (por exemplo, checando por erros) antes de propagá-lo pela rede.48

A comutação de pacotes permite que múltiplos pacotes de diferentes comunicações compartilhem os mesmos enlaces de rede. Os pacotes são enfileirados nos roteadores e transmitidos assim que o enlace fica disponível, um processo análogo a carros de diferentes origens e destinos compartilhando a mesma rodovia. Isso leva a uma utilização muito mais eficiente dos recursos da rede em comparação com a alternativa, a comutação de circuitos.46 Além disso, como os pacotes de uma mesma mensagem podem seguir rotas diferentes para o destino, a rede se torna inerentemente resiliente a falhas; se um link cair, os roteadores podem simplesmente desviar os pacotes subsequentes por um caminho alternativo.52 Essa abordagem, que pode parecer caótica, é a chave para a escalabilidade e a robustez que permitiram o crescimento fenomenal da Internet.

### 1.3.2 Comutação de circuitos

Em contraste direto com a comutação de pacotes, a comutação de circuitos estabelece um caminho de comunicação dedicado e exclusivo entre dois pontos finais antes que qualquer dado seja transferido.45 O exemplo mais clássico é a rede telefônica pública tradicional (PSTN).44

O processo de comunicação em uma rede de comutação de circuitos ocorre em três fases distintas 44:

1. **Estabelecimento do Circuito**: Quando uma chamada é iniciada, um sinal é enviado através da rede para reservar recursos (como canais de frequência ou intervalos de tempo) em cada comutador ao longo de um caminho da origem ao destino. Isso cria um circuito fim a fim com uma largura de banda fixa e garantida.44
2. **Transferência de Dados**: Uma vez que o circuito é estabelecido, as partes podem se comunicar. Os dados fluem continuamente através do caminho dedicado com uma taxa de transmissão e um atraso constantes, sem sofrer com congestionamento de outras comunicações.44
3. **Desconexão do Circuito**: Quando a comunicação termina, um sinal de desconexão é enviado para liberar os recursos alocados em todos os comutadores do caminho, tornando-os disponíveis para outras chamadas.53

A principal vantagem da comutação de circuitos é a garantia da qualidade de serviço (QoS). Como os recursos são dedicados, não há perda de pacotes ou variação no atraso (jitter) devido ao congestionamento, o que a torna ideal para aplicações de voz em tempo real.45 No entanto, sua principal desvantagem é a ineficiência. Os recursos do circuito permanecem alocados exclusivamente para a chamada, mesmo durante os períodos de silêncio, resultando em um desperdício significativo de largura de banda.45

A tabela a seguir resume as diferenças fundamentais entre os dois paradigmas de comutação.

**Tabela 2: Comutação de Pacotes vs. Comutação de Circuitos**

| Característica | Comutação de Circuitos | Comutação de Pacotes |
|----------------|------------------------|-----------------------|
| **Alocação de Recursos** | Recursos (largura de banda, buffers) dedicados e reservados para toda a duração da comunicação. | Recursos compartilhados sob demanda; sem reserva prévia. |
| **Rota** | Um único caminho fixo é estabelecido e usado durante toda a sessão. | Pacotes podem seguir rotas diferentes e dinâmicas da origem ao destino. |
| **Qualidade de Serviço** | Taxa de transmissão e atraso constantes e garantidos. Sem perda por congestionamento. | Sem garantias. Desempenho (atraso, vazão) pode variar com o congestionamento da rede. Possibilidade de perda de pacotes. |
| **Eficiência de Recursos** | Baixa. Recursos ficam ociosos se não houver dados sendo transmitidos. | Alta. A largura de banda é utilizada por qualquer comunicação que tenha pacotes para enviar. |
| **Custo** | Mais caro devido à reserva de recursos dedicados. | Mais barato e escalável devido ao compartilhamento de recursos. |
| **Exemplo Principal** | Rede Telefônica Tradicional (PSTN). | A Internet. |

*Fontes: 44*

### 1.3.3 Uma rede de redes

A Internet não é uma entidade monolítica, mas sim uma "rede de redes".1 É uma vasta interconexão de dezenas de milhares de redes individuais, conhecidas como Sistemas Autônomos (AS), cada uma operada por uma entidade diferente, como um Provedor de Serviços de Internet (ISP), uma universidade ou uma grande empresa. A estrutura da Internet é, portanto, definida pela forma como essas redes se conectam e trocam tráfego entre si. Essa estrutura é largamente hierárquica e baseada em relações comerciais.58

**A Hierarquia de ISPs**: Os ISPs são geralmente categorizados em três Tiers (camadas):

- **Tier 1**: São os gigantes da Internet, a espinha dorsal global. Possuem e operam vastas redes transcontinentais e submarinas.59 A característica definidora de um ISP Tier 1 é que ele pode alcançar todas as outras redes na Internet sem pagar por isso. Eles fazem acordos de peering (troca de tráfego sem custo) entre si, com base no benefício mútuo de conectar suas enormes bases de clientes.58 Eles vendem acesso à Internet, conhecido como trânsito, para ISPs de Tiers inferiores. Exemplos incluem AT&T, Verizon e Deutsche Telekom.58
- **Tier 2**: São ISPs de grande porte, geralmente com alcance regional ou nacional. Eles fazem peering com outros ISPs Tier 2 para trocar tráfego localmente, mas precisam comprar trânsito de um ou mais ISPs Tier 1 para garantir a conectividade global.58
- **Tier 3**: São ISPs locais que fornecem o acesso de "última milha" aos usuários finais (residenciais e pequenas empresas). Eles quase exclusivamente compram trânsito de ISPs de Tier 2 ou Tier 1 para se conectar ao resto da Internet.58

**Pontos de Troca de Tráfego (PTT / IXP)**: Para facilitar a interconexão, especialmente entre ISPs de Tier 2 e Tier 3, foram criados os Pontos de Troca de Tráfego (PTTs), internacionalmente conhecidos como Internet Exchange Points (IXPs).63 Um IXP é uma infraestrutura física (um data center com comutadores de alta velocidade) onde dezenas ou centenas de ISPs podem se conectar e trocar tráfego diretamente entre si, através de acordos de peering.64 Isso é muito mais eficiente e barato do que enviar o tráfego local através de um provedor de trânsito Tier 1 distante. No Brasil, o IX.br é o projeto do Comitê Gestor da Internet no Brasil (CGI.br) que opera a infraestrutura de IXPs em todo o país, sendo fundamental para a eficiência, velocidade e baixo custo da Internet brasileira.66

Essa estrutura revela que a topologia e o fluxo de dados na Internet são moldados tanto por engenharia quanto por economia. As decisões de peering e trânsito são acordos de negócios que determinam os caminhos que os pacotes percorrem, tornando a Internet um sistema socioeconômico complexo, além de uma maravilha técnica.

## 1.4 Atraso, perda e vazão em redes de comutação de pacotes

O desempenho de uma rede de comutação de pacotes, do ponto de vista do usuário, é medido principalmente por três métricas: atraso (ou latência), perda de pacotes e vazão (ou throughput). Esses fatores determinam a rapidez e a confiabilidade com que os dados atravessam a rede.

### 1.4.1 Uma visão geral de atraso

Quando um pacote viaja da origem ao destino, ele sofre vários tipos de atraso em cada nó (roteador) que atravessa. O atraso total em um nó, conhecido como atraso nodal, é a soma de quatro componentes 67:

1. **Atraso de Processamento (dproc)**: O tempo necessário para o roteador examinar o cabeçalho do pacote, verificar se há erros de bits e determinar para qual enlace de saída o pacote deve ser encaminhado. Esse atraso é tipicamente da ordem de microssegundos.68
2. **Atraso de Fila (dfila)**: O tempo que um pacote passa esperando em uma fila (buffer) para ser transmitido no enlace de saída. Este atraso depende diretamente do nível de congestionamento no roteador e é a componente mais variável do atraso total.68
3. **Atraso de Transmissão (dtrans)**: O tempo necessário para "empurrar" todos os bits do pacote para o enlace de comunicação. Este atraso é determinado pelo tamanho do pacote (L, em bits) e pela taxa de transmissão do enlace (R, em bits por segundo). A fórmula é dtrans=L/R. Por exemplo, para enviar um pacote de 1.500 bytes (12.000 bits) por um link de 100 Mbps, o atraso de transmissão seria de 12.000/100.000.000=0,12 milissegundos.68
4. **Atraso de Propagação (dprop)**: O tempo que um bit lega para viajar do início ao fim do enlace físico. Este atraso é determinado pela distância do enlace (d, em metros) e pela velocidade de propagação do sinal no meio (s, que é próxima da velocidade da luz, cerca de 2×108 m/s em fibra). A fórmula é dprop=d/s. Este atraso é insignificante em LANs, mas pode ser de dezenas de milissegundos em links transoceânicos.69

É crucial distinguir entre o atraso de transmissão e o de propagação. Uma analogia útil é a de uma caravana de carros viajando por uma rodovia.67 O atraso de transmissão é o tempo que leva para toda a caravana (o pacote) passar pelo portão de pedágio (o roteador). O atraso de propagação é o tempo que o primeiro carro leva para viajar do portão de pedágio até o próximo.

### 1.4.2 Atraso de fila e perda de pacote

O atraso de fila é o principal culpado pela sensação de "lentidão" na Internet. Ele ocorre porque os roteadores têm buffers (filas) de saída de tamanho finito para armazenar pacotes que aguardam a transmissão.73 Se os pacotes chegam à fila mais rápido do que o enlace de saída pode transmiti-los, a fila começa a crescer, e com ela, o atraso de fila.71

A intensidade de tráfego, uma razão adimensional dada por La/R (onde L é o tamanho médio do pacote, a é a taxa média de chegada de pacotes e R é a taxa de transmissão do enlace), é um indicador chave do atraso de fila.

- Se La/R≈0, o atraso de fila é mínimo.
- À medida que La/R→1, o atraso de fila cresce exponencialmente, tendendo ao infinito.
- Se La/R>1, a fila cresceria indefinidamente se os buffers fossem infinitos.69

Como os buffers são finitos, quando um pacote chega a um roteador e encontra a fila de saída completamente cheia, o roteador não tem outra opção a não ser descartar esse pacote. Isso é conhecido como perda de pacote.69 As principais causas da perda de pacotes são o congestionamento da rede (a causa mais comum), problemas de hardware (roteadores defeituosos), bugs de software e ataques de segurança.75

Embora a perda de pacotes seja prejudicial para as aplicações, ela desempenha um papel fundamental na estabilidade da Internet. Protocolos de transporte confiáveis, como o TCP, usam a perda de pacotes como um sinal implícito de que a rede está congestionada. Ao detectar uma perda, o remetente TCP reduz sua taxa de envio, aliviando a carga na rede.76 Portanto, a perda de pacotes não é apenas uma falha, mas um mecanismo de feedback essencial que permite à Internet se autorregular e evitar o colapso por congestionamento.

### 1.4.3 Atraso fim a fim

O atraso fim a fim de um pacote é a soma de todos os atrasos nodais (processamento, fila, transmissão e propagação) em cada um dos N roteadores ao longo do caminho da origem ao destino.67 A fórmula geral pode ser expressa como:

dfim−a−fim = N × (dproc + dfila + dtrans + dprop)

Na prática, os atrasos de processamento e propagação são frequentemente considerados fixos para um dado caminho, enquanto o atraso de fila é a principal fonte de variabilidade. Ferramentas de diagnóstico como ping e traceroute são usadas para medir o tempo de ida e volta (Round-Trip Time - RTT) e para identificar os saltos (hops) ao longo de um caminho, respectivamente, ajudando a diagnosticar problemas de latência.72

### 1.4.4 Vazão nas redes

A vazão (ou throughput) é a taxa real, medida em bits por segundo, na qual os dados são transferidos com sucesso entre uma origem e um destino.68 É importante distinguir vazão de largura de banda. A largura de banda é a taxa de transmissão máxima teórica de um link, enquanto a vazão é o desempenho real alcançado.

A vazão fim a fim em uma rede é frequentemente limitada pelo link mais lento no caminho, conhecido como gargalo (bottleneck).81 Por exemplo, se um usuário com uma conexão de fibra de 1 Gbps está baixando um arquivo de um servidor conectado à Internet por um link de 100 Mbps, a vazão máxima que ele poderá alcançar será de 100 Mbps, pois o link do servidor é o gargalo.81 A vazão não é uma propriedade de um único componente, mas uma métrica emergente de todo o sistema fim a fim. Identificar e mitigar gargalos, que podem ser causados por limitações de hardware, software ou congestionamento de rede, é uma tarefa central no gerenciamento de desempenho.81

## 1.5 Camadas de protocolo e seus modelos de serviço

Gerenciar a imensa complexidade de uma rede global como a Internet seria uma tarefa impossível sem um princípio de organização estruturado. A solução para essa complexidade é a arquitetura de camadas, uma abordagem que divide o problema da comunicação de rede em partes menores e mais gerenciáveis.

### 1.5.1 Arquitetura de camadas

A ideia fundamental da arquitetura de camadas é que cada camada fornece serviços para a camada imediatamente superior, utilizando os serviços da camada imediatamente inferior.84 Cada camada se preocupa apenas com suas próprias funções e interage com as camadas adjacentes através de interfaces bem definidas. Isso cria um design modular, onde a implementação de uma camada pode ser alterada sem afetar as outras, desde que a interface de serviço permaneça a mesma.85

Existem dois modelos de camadas principais em redes de computadores:

- **Modelo OSI (Open Systems Interconnection)**: Desenvolvido pela International Organization for Standardization (ISO), o OSI é um modelo de referência teórico com sete camadas. Ele serve como um guia conceitual para entender as funções da rede.86 Suas sete camadas, da mais baixa para a mais alta, são 85:
  1. **Física**: Transmissão de bits brutos sobre o meio físico.
  2. **Enlace de Dados**: Transferência de dados entre nós vizinhos em uma mesma rede (por exemplo, Ethernet), com controle de erros.
  3. **Rede**: Endereçamento lógico (endereços IP) e roteamento de pacotes através de múltiplas redes.
  4. **Transporte**: Fornece serviços de comunicação de processo a processo, incluindo entrega confiável (TCP) e não confiável (UDP).
  5. **Sessão**: Gerenciamento de sessões de comunicação entre aplicações.
  6. **Apresentação**: Tradução de dados, criptografia e compressão.
  7. **Aplicação**: Fornece serviços de rede diretamente para as aplicações do usuário (por exemplo, HTTP, SMTP).

- **Modelo TCP/IP**: Este é o modelo prático sobre o qual a Internet foi construída. É mais simples e combina algumas das funções do modelo OSI em menos camadas.86 Uma representação comum do modelo TCP/IP possui quatro camadas 18:
  1. **Interface de Rede (ou Enlace)**: Corresponde às camadas Física e de Enlace do OSI.
  2. **Internet**: Corresponde à camada de Rede do OSI (Protocolo IP).
  3. **Transporte**: Corresponde à camada de Transporte do OSI (Protocolos TCP e UDP).
  4. **Aplicação**: Combina as camadas de Sessão, Apresentação e Aplicação do OSI.

As vantagens de uma arquitetura em camadas são imensas: modularidade, facilidade de manutenção e padronização. Ela permite que especialistas trabalhem em protocolos para uma camada específica sem precisar conhecer os detalhes das outras, promovendo a inovação e a interoperabilidade.84

### 1.5.2 Encapsulamento

O encapsulamento é o mecanismo prático que permite o funcionamento da arquitetura de camadas. Quando uma aplicação em um host de origem envia dados, esses dados descem pela pilha de protocolos. Em cada camada, a unidade de dados da camada superior é tratada como uma "caixa preta" de dados, e a camada atual adiciona seu próprio cabeçalho (e, às vezes, um trailer) contendo informações de controle.88

O processo pode ser visualizado da seguinte forma 88:

1. Na **Camada de Aplicação**, a mensagem é criada.
2. A mensagem é passada para a **Camada de Transporte**. O protocolo de transporte (por exemplo, TCP) adiciona um cabeçalho (com informações como números de porta de origem e destino) à mensagem. A unidade de dados resultante é chamada de segmento.
3. O segmento é passado para a **Camada de Rede**. O protocolo de rede (IP) adiciona seu próprio cabeçalho (com os endereços IP de origem e destino). A unidade de dados resultante é chamada de pacote (ou datagrama).
4. O pacote é passado para a **Camada de Enlace**. O protocolo de enlace (por exemplo, Ethernet) adiciona um cabeçalho e um trailer (com endereços físicos, como o endereço MAC). A unidade de dados resultante é chamada de quadro (frame).
5. Finalmente, a **Camada Física** transmite o quadro como uma sequência de bits pelo meio físico.

No host de destino, ocorre o processo inverso, o desencapsulamento. À medida que os dados sobem pela pilha, cada camada remove e processa o cabeçalho correspondente, passando os dados restantes para a camada superior, até que a mensagem original chegue à aplicação de destino.91

Essa ocultação de informações é a chave para a independência das camadas. A camada de rede não precisa saber o que está dentro do segmento TCP que ela está encapsulando; ela apenas faz seu trabalho de rotear o pacote com base no endereço IP. Isso permite, por exemplo, que a Internet funcione sobre qualquer tecnologia de camada de enlace (Ethernet, Wi-Fi, etc.) sem que as camadas superiores precisem ser modificadas.

## 1.6 Redes sob ameaça

A arquitetura aberta e a filosofia de design da Internet, que priorizaram a conectividade e a resiliência em um ambiente de pesquisa confiável, também a deixaram vulnerável a uma variedade de ameaças de segurança. A segurança na Internet moderna é, em grande parte, um esforço para adaptar uma infraestrutura fundamentalmente baseada na confiança a um mundo onde atores mal-intencionados são uma realidade constante.

Os principais vetores de ataque incluem:

- **Malware**: Abreviação de "software malicioso", é um termo genérico para qualquer software projetado para se infiltrar, danificar ou obter acesso não autorizado a um sistema de computador.92 O malware se propaga quando um usuário é enganado a executar uma ação, como clicar em um link malicioso, abrir um anexo de e-mail infectado ou visitar um site comprometido.94 Seus tipos incluem vírus, worms, spyware e cavalos de Troia (Trojans), que se disfarçam de software legítimo para obter acesso, e ransomware, que criptografa os arquivos da vítima e exige um resgate para sua liberação.
- **Ataques de Negação de Serviço (DoS e DDoS)**: O objetivo de um ataque de Negação de Serviço (DoS) é tornar um recurso de rede (como um site ou servidor) indisponível para seus usuários legítimos, inundando-o com uma quantidade esmagadora de tráfego ou solicitações malformadas.95 Um ataque de Negação de Serviço Distribuída (DDoS) é uma forma mais potente e difícil de mitigar, na qual o tráfego de ataque é originado de múltiplas fontes comprometidas simultaneamente.97 Essas fontes são geralmente computadores ou dispositivos IoT que foram infectados com malware e organizados em uma botnet, uma rede de "robôs" que podem ser controlados remotamente pelo invasor para lançar ataques coordenados.97
- **Interceptação de Pacotes (Packet Sniffing)**: Esta técnica envolve o uso de software ou hardware especializado (um sniffer) para capturar, registrar e analisar os pacotes de dados que trafegam por uma rede.99 Se os dados não estiverem criptografados, um invasor pode ler informações sensíveis diretamente dos pacotes capturados, como senhas, conteúdo de e-mails e dados financeiros.102 Embora o sniffing seja uma ferramenta legítima e essencial para administradores de rede diagnosticarem problemas, seu uso malicioso constitui uma grave violação de privacidade e segurança.99
- **Falsificação de IP (IP Spoofing)**: Nesta técnica, um invasor cria pacotes IP com um endereço de origem falso no cabeçalho.104 O objetivo é ocultar a identidade do remetente ou se passar por outro computador confiável.106 O IP spoofing é um componente chave em muitos ataques DDoS, pois dificulta o rastreamento da origem do ataque e o bloqueio do tráfego malicioso. Também pode ser usado em ataques man-in-the-middle, onde um invasor se insere em uma comunicação existente para interceptar ou modificar os dados.106

A tabela a seguir resume essas ameaças e as contramedidas comuns.

**Tabela 3: Vetores de Ameaça e Mecanismos de Defesa**

| Vetor de Ameaça | Mecanismo de Ataque | Objetivo Principal | Mecanismos de Defesa Comuns |
|------------------|----------------------|--------------------|------------------------------|
| **Malware** | Infiltração de software malicioso via phishing, downloads, etc. | Roubo de dados, extorsão (ransomware), controle do sistema. | Software antivírus/antimalware, firewalls, educação do usuário, manter o software atualizado. |
| **DDoS** | Sobrecarregar o alvo com tráfego massivo de uma botnet. | Tornar o serviço indisponível para usuários legítimos. | Filtragem de tráfego, sistemas de detecção de intrusão (IDS), serviços de mitigação de DDoS baseados em nuvem. |
| **Packet Sniffing** | Captura e análise de pacotes de rede. | Roubo de informações confidenciais (senhas, dados financeiros). | Criptografia de ponta a ponta (ex: HTTPS, VPNs), uso de redes comutadas (switched) em vez de hubs. |
| **IP Spoofing** | Falsificação do endereço IP de origem em pacotes. | Ocultar a identidade, se passar por um host confiável, facilitar ataques DDoS. | Filtragem de ingresso e egresso em roteadores (anti-spoofing), protocolos de autenticação. |

*Fontes: 75*

## 1.7 História das redes de computadores e da Internet

A Internet de hoje é o resultado de décadas de pesquisa, desenvolvimento e evolução, moldada por necessidades militares, acadêmicas e, finalmente, comerciais. Sua história pode ser dividida em várias eras distintas.

### 1.7.1 Comutação de pacotes: 1961–1972

As raízes da Internet remontam ao auge da Guerra Fria. O trabalho teórico pioneiro de Leonard Kleinrock no MIT (1961) sobre a teoria das filas e de Paul Baran na RAND Corporation (1964) sobre redes militares demonstrou que a comutação de pacotes era uma abordagem viável e eficiente para a comunicação de dados.107 A motivação era criar uma rede de comando e controle descentralizada que pudesse sobreviver a falhas parciais, como um ataque nuclear.109

Este trabalho culminou na criação da ARPANET pela Advanced Research Projects Agency (ARPA) do Departamento de Defesa dos EUA.108 A rede entrou em operação em 1969, conectando inicialmente quatro nós em universidades americanas.110 Em 1972, a ARPANET foi demonstrada publicamente com sucesso, já contando com 15 nós. Durante este período, foram desenvolvidos o primeiro protocolo host-a-host, o Network Control Protocol (NCP), e a primeira aplicação "matadora": o e-mail.108

### 1.7.2 Redes proprietárias: 1972–1980

Com o sucesso da ARPANET, o foco se deslocou para um desafio ainda maior: como interconectar redes diferentes e heterogêneas (um processo chamado internetworking). A ARPANET precisava se comunicar com novas redes baseadas em satélite (ALOHAnet) e rádio.107

Em 1974, Vinton Cerf e Robert Kahn publicaram a arquitetura fundamental para a interconexão de redes, que se tornaria o TCP/IP.111 Seus princípios de design — uma rede minimalista e autônoma, um serviço de "melhor esforço" (best-effort), roteadores sem estado e controle descentralizado — são os que definem a arquitetura da Internet até hoje.111

Enquanto a comunidade de pesquisa da ARPA trabalhava nesta abordagem aberta e universal, grandes corporações como a DEC e a IBM desenvolviam suas próprias arquiteturas de rede fechadas e proprietárias, como a DECnet e a SNA.111 Este período foi marcado por uma batalha de visões: um futuro de redes abertas e interconectadas versus um futuro de "ilhas" de redes proprietárias e incompatíveis.

### 1.7.3 Proliferação de redes: 1980–1990

A década de 1980 viu a vitória e a consolidação da abordagem TCP/IP. Em 1º de janeiro de 1983, a ARPANET adotou oficialmente o TCP/IP como seu protocolo padrão, um marco crucial.114 Com o crescimento contínuo da rede, o sistema manual de mapeamento de nomes de hosts para endereços tornou-se impraticável. Para resolver esse problema de escala, o Sistema de Nomes de Domínio (DNS) foi introduzido em 1983, criando o sistema hierárquico de nomes (como .com, .edu) que usamos hoje.111

O desenvolvimento mais significativo da década foi a criação da NSFNET em 1986 pela National Science Foundation (NSF) dos EUA.116 A NSFNET começou como um backbone de 56 kbps para conectar cinco centros de supercomputação, mas rapidamente se expandiu para conectar redes de pesquisa e educação em todo o país e, eventualmente, em todo o mundo.115 A NSFNET efetivamente substituiu a ARPANET (que foi desativada em 1990) como a espinha dorsal da Internet, catalisando sua transformação de um projeto militar para uma infraestrutura de pesquisa global.115

### 1.7.4 A explosão da Internet: década de 1990

A década de 1990 foi o período em que a Internet passou de um domínio de acadêmicos e pesquisadores para um fenômeno global de massa. Essa explosão foi impulsionada pela confluência de três desenvolvimentos cruciais:

1. **A Invenção da World Wide Web**: Em 1989-1990, Tim Berners-Lee, um cientista do CERN, inventou a World Wide Web (WWW). Ele desenvolveu os conceitos fundamentais de URL (endereços web), HTTP (protocolo de transferência de hipertexto) e HTML (linguagem de marcação de hipertexto), criando um sistema para navegar e interligar informações de forma intuitiva.118
2. **A Comercialização da Rede**: Em 1991, a NSF removeu suas restrições sobre o uso comercial da NSFNET, abrindo as portas para empresas e o público em geral.111 A própria NSFNET foi desativada em 1995, transferindo o tráfego do backbone para provedores comerciais.116
3. **O Surgimento do Navegador Gráfico**: Em 1993, foi lançado o Mosaic, o primeiro navegador web gráfico e fácil de usar, desenvolvido na NCSA.118 O Mosaic (e seu sucessor comercial, Netscape) tornou a Web acessível a não especialistas, transformando a Internet em uma experiência visual e interativa.

Essa combinação perfeita de uma infraestrutura robusta (a Internet baseada em TCP/IP), uma política de abertura comercial e uma aplicação "matadora" com uma interface amigável (a Web e seus navegadores) levou a um crescimento exponencial. No final da década, a Internet já contava com dezenas de milhões de computadores conectados e mais de 100 milhões de usuários.111

### 1.7.5 O novo milênio

O século XXI testemunhou a maturação da Internet e sua integração em quase todos os aspectos da vida moderna. A transição do acesso discado para a banda larga "always-on" (sempre ativa) no início dos anos 2000 foi o primeiro grande catalisador, permitindo aplicações ricas em mídia como o streaming de vídeo.122

A seguir, a revolução da Internet móvel, impulsionada pela proliferação de smartphones a partir de 2007, tornou o acesso à rede onipresente. A computação em nuvem (cloud computing) mudou o paradigma de computação, movendo o armazenamento de dados e o processamento de dispositivos locais para data centers massivos e escaláveis, fornecendo a infraestrutura para serviços como Netflix, Google Drive e inúmeras aplicações empresariais.122

As redes sociais (Facebook, Twitter, Instagram) redefiniram a comunicação e a interação social. Mais recentemente, a Internet das Coisas (IoT) começou a conectar bilhões de dispositivos físicos do dia a dia — de eletrodomésticos a sensores industriais — à Internet, gerando enormes volumes de dados e abrindo novas fronteiras para automação e análise.122 A trajetória da Internet no novo milênio tem sido de aumento contínuo de velocidade, ubiquidade e escopo, construindo sobre as fundações estabelecidas nas décadas anteriores.