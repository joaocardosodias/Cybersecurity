# Relatório Abrangente sobre a Camada de Rede: Arquitetura, Protocolos e Algoritmos

## 4.1 Introdução à Camada de Rede

A camada de rede, ou Camada 3 no modelo de referência OSI, constitui o cerne da comunicação de dados em redes de grande escala como a Internet. Sua função primordial é prover conectividade lógica de ponta a ponta (fim-a-fim) entre sistemas finais (hosts), permitindo que pacotes de dados, conhecidos como datagramas, viajem de uma origem a um destino através de um complexo sistema de redes interconectadas.¹ Se a camada de transporte é responsável pela comunicação lógica entre processos (aplicações), a camada de rede é responsável pela comunicação lógica entre hosts.³

Para realizar essa tarefa, a camada de rede desempenha duas funções críticas e distintas: o repasse (forwarding) e o roteamento (routing). Utilizando uma analogia com um serviço postal global, a camada de rede é o sistema logístico que garante que uma carta (pacote de dados) postada em uma cidade (rede de origem) chegue ao endereço correto em uma cidade distante (rede de destino), independentemente do número de centros de triagem (roteadores) e rotas de transporte (enlaces) que precise atravessar.

### 4.1.1 Repasse (Forwarding) e Roteamento (Routing)

Embora frequentemente usados de forma intercambiável, repasse e roteamento são duas funções distintas, operando em escalas de tempo e escopos diferentes dentro da camada de rede.³

#### Repasse (Forwarding)

O repasse é a ação local e de curtíssimo prazo de mover um pacote de uma porta de entrada de um roteador para a porta de saída apropriada.³ Quando um pacote chega, o roteador examina seu cabeçalho para determinar o destino e, com base nessa informação, o transfere internamente para a interface de saída correta. Essa função é executada pelo plano de dados (data plane) do roteador, que é otimizado para operar em alta velocidade, muitas vezes na velocidade do enlace (wire speed).⁶

Para tomar essa decisão de forma quase instantânea, o plano de dados utiliza uma estrutura de dados chamada tabela de encaminhamento (ou tabela de repasse). Essa tabela é uma lista que mapeia endereços de destino ou prefixos de rede para as interfaces de saída do roteador.² Na analogia postal, o repasse é o ato de um funcionário em um centro de triagem olhar para o CEP de um pacote e colocá-lo na esteira correta que leva ao caminhão destinado à cidade de destino. É uma ação mecânica, local e rápida.⁴

#### Roteamento (Routing)

O roteamento, por outro lado, é o processo global e de longo prazo que determina o caminho de ponta a ponta que os pacotes seguirão da origem ao destino.³ Esta função é executada pelo plano de controle (control plane) do roteador.⁶ O plano de controle utiliza algoritmos de roteamento para se comunicar com outros roteadores, trocando informações sobre a topologia da rede e o estado dos enlaces. Com base nessas informações, ele calcula os melhores caminhos e, crucialmente, constrói e atualiza a tabela de encaminhamento que será usada pelo plano de dados.⁴

Continuando a analogia postal, o roteamento é o processo logístico que define as rotas de transporte entre as cidades. Envolve analisar mapas, condições de tráfego e custos para criar as diretrizes que todos os centros de triagem usarão. É um processo de planejamento estratégico que abrange toda a rede.⁴

A separação entre o plano de controle e o plano de dados é um dos princípios de design mais importantes da arquitetura de redes. O roteamento (plano de controle) é a "inteligência" que calcula as rotas, enquanto o repasse (plano de dados) é a "força bruta" que executa o encaminhamento em alta velocidade. Esta separação lógica dentro dos roteadores tradicionais foi o alicerce que permitiu a emergência das Redes Definidas por Software (SDN), onde o plano de controle é fisicamente desacoplado e centralizado, gerenciando remotamente o plano de dados de múltiplos dispositivos de rede.¹⁰

### 4.1.2 Modelos de Serviço

O modelo de serviço da camada de rede define as características da entrega de pacotes entre os hosts de origem e destino. Ele especifica o nível de garantia que uma aplicação pode esperar da rede em termos de entrega, atraso, ordem e largura de banda.³

#### Serviço de Melhor Esforço (Best-Effort Service)

Este é o modelo de serviço adotado pela arquitetura da Internet e seu protocolo IP. Sob este modelo, a rede não oferece garantias explícitas.¹¹ Os pacotes são enviados com o "melhor esforço" possível, o que significa que:

- **Não há garantia de entrega**: Pacotes podem ser perdidos devido a congestionamento ou erros de transmissão.
- **Não há garantia de ordem**: Pacotes da mesma comunicação podem seguir rotas diferentes e chegar ao destino fora da ordem em que foram enviados.
- **Não há garantia de tempo**: O atraso (latência) de cada pacote pode variar significativamente (jitter).
- **Não há garantia de largura de banda**: A taxa de transferência disponível para uma aplicação pode flutuar drasticamente.

A principal vantagem deste modelo é a simplicidade e a robustez do núcleo da rede. Os roteadores não precisam manter estado sobre os fluxos de dados, tornando a arquitetura mais escalável e resiliente a falhas. A responsabilidade por fornecer confiabilidade (como retransmissão de pacotes perdidos e reordenação) é delegada às camadas superiores, especificamente à camada de transporte, através de protocolos como o TCP. Esta filosofia de design é um pilar do "princípio fim-a-fim", que defende que a inteligência e o controle devem residir nas bordas da rede (sistemas finais) em vez de no seu núcleo.¹¹

#### Serviços com Garantias

Em contraste, outras arquiteturas de rede, como o Asynchronous Transfer Mode (ATM), foram projetadas para oferecer modelos de serviço com garantias explícitas, mais adequados para aplicações em tempo real como voz e vídeo.³ Exemplos incluem:

- **Taxa de Bits Constante (CBR - Constant Bit Rate)**: Garante uma taxa de bits fixa e um atraso constante, emulando um circuito dedicado. É ideal para tráfego de voz não comprimido.¹²
- **Taxa de Bits Disponível (ABR - Available Bit Rate)**: Garante uma taxa de bits mínima, mas permite que a aplicação utilize mais largura de banda se houver capacidade ociosa na rede.¹²

Esses serviços exigem que a rede estabeleça uma conexão antes da transferência de dados e que os roteadores realizem gerenciamento de recursos, como reserva de largura de banda e buffers, tornando o núcleo da rede significativamente mais complexo.

## 4.2 Circuitos Virtuais e Datagramas

As duas abordagens fundamentais para a comutação de pacotes na camada de rede são as redes de circuitos virtuais e as redes de datagramas. Elas representam a implementação prática dos modelos de serviço orientado à conexão e sem conexão, respectivamente.

### 4.2.1 Redes de Circuitos Virtuais

Uma rede de Circuito Virtual (VC) opera de maneira análoga a uma rede telefônica, estabelecendo uma conexão lógica de ponta a ponta antes que os dados comecem a fluir.¹⁴ Um VC consiste em um caminho específico (uma sequência de enlaces e roteadores), um número de VC para cada enlace nesse caminho e entradas nas tabelas de encaminhamento de cada roteador ao longo do percurso.¹⁷

A comunicação em uma rede VC ocorre em três fases distintas:

1. **Estabelecimento do VC**: O host de origem envia uma mensagem de sinalização para a rede para iniciar a conexão. A rede determina uma rota da origem ao destino, e cada roteador ao longo desse caminho cria uma entrada em sua tabela de encaminhamento para esta nova conexão, alocando um número de VC para o enlace de entrada e um para o de saída. Recursos como largura de banda podem ser reservados nesta fase.¹⁴

2. **Transferência de Dados**: Uma vez que o VC está estabelecido, os pacotes de dados podem ser enviados. Cada pacote carrega um número de VC em seu cabeçalho. Os roteadores não precisam analisar o endereço de destino completo; eles simplesmente usam o número de VC de entrada e a porta de entrada para consultar sua tabela de encaminhamento e determinar a porta de saída e o novo número de VC para o pacote.¹⁶

3. **Desconexão do VC**: Quando a comunicação termina, uma das partes envia uma mensagem de sinalização para encerrar a conexão. Os roteadores ao longo do caminho removem as entradas correspondentes de suas tabelas de encaminhamento, liberando os recursos.¹⁹

Neste modelo, os roteadores mantêm estado de conexão, o que significa que eles armazenam informações sobre cada VC ativo que passa por eles. Exemplos de tecnologias que utilizam circuitos virtuais incluem ATM, Frame Relay e X.25.¹⁹

### 4.2.2 Redes de Datagramas

As redes de datagramas adotam uma abordagem sem conexão. Não há fase de estabelecimento de conexão; a rede simplesmente aceita os pacotes e os encaminha com base nas informações contidas em seus cabeçalhos.²¹ A Internet é o principal exemplo de uma rede de datagramas.¹⁹

As características principais são:

- **Endereçamento Completo**: Cada pacote, ou datagrama, deve conter o endereço de destino completo em seu cabeçalho para que os roteadores possam encaminhá-lo corretamente.²⁴

- **Roteadores Sem Estado (Stateless)**: Os roteadores em uma rede de datagramas não mantêm informações de estado sobre as conexões. Cada datagrama é tratado de forma independente. A decisão de encaminhamento é baseada unicamente no endereço de destino do pacote e na tabela de roteamento do roteador.²³

- **Roteamento Dinâmico**: Como cada pacote é roteado de forma independente, pacotes pertencentes à mesma comunicação podem seguir caminhos diferentes pela rede. Isso oferece grande robustez: se um roteador falhar, os pacotes subsequentes podem ser automaticamente desviados por rotas alternativas.²⁷ A desvantagem é que os pacotes podem chegar ao destino fora de ordem, exigindo que a camada de transporte os reordene.

### 4.2.3 Origens Históricas

A escolha entre circuitos virtuais e datagramas reflete diferentes filosofias de design de rede. As redes de circuitos virtuais têm suas raízes nas redes de telecomunicações, como a rede telefônica, que se baseia na comutação de circuitos. Na comutação de circuitos, um caminho físico dedicado e com recursos garantidos é estabelecido para a duração de uma chamada, o que é ideal para o tráfego de voz de taxa constante.²⁸

Por outro lado, a Internet, originada da ARPANET, foi projetada como uma rede de datagramas. Os principais objetivos eram criar uma rede descentralizada e resiliente, capaz de sobreviver a falhas de componentes individuais, como roteadores. Em uma rede de datagramas, se um roteador falha, o tráfego pode ser dinamicamente redirecionado por caminhos alternativos. Em uma rede de circuitos virtuais, a falha de um roteador interrompe todos os VCs que passam por ele, exigindo um novo processo de estabelecimento de conexão.²⁷ A simplicidade do núcleo da rede, empurrando a complexidade para os sistemas finais (hosts), foi outro fator decisivo que permitiu a escalabilidade e o crescimento massivo da Internet.

| Característica | Redes de Circuitos Virtuais (VC) | Redes de Datagramas |
|---|---|---|
| Natureza da Conexão | Orientada à conexão | Sem conexão |
| Estabelecimento de Rota | Rota fixa estabelecida antes da transferência | Rota determinada pacote a pacote |
| Estado no Roteador | Roteadores mantêm estado por conexão | Roteadores são "stateless" (sem estado) |
| Endereçamento de Pacote | Usa um identificador de VC de escopo local | Usa endereço de destino global completo |
| Ordem dos Pacotes | Chegam em ordem | Podem chegar fora de ordem |
| Garantia de Recursos | Possível (reserva de buffers/largura de banda) | Não há garantias (melhor esforço) |
| Complexidade do Núcleo | Alta (gerenciamento de conexões) | Baixa (simples encaminhamento) |
| Exemplos de Protocolos | ATM, Frame Relay, X.25 | IP (Internet) |

## 4.3 Dentro de um Roteador

Um roteador é um dispositivo de rede especializado cujo propósito principal é encaminhar pacotes de dados entre redes de computadores. Sua arquitetura interna é projetada para realizar essa tarefa com a máxima velocidade e eficiência possíveis, dividindo suas funções entre o plano de dados e o plano de controle.

### 4.3.1 Entrada, Comutação, Saída

A arquitetura genérica de um roteador pode ser decomposta em quatro componentes principais: portas de entrada, portas de saída, estrutura de comutação e o processador de roteamento.¹

**Portas de Entrada**: Uma porta de entrada executa múltiplas funções. Na camada física, ela termina um enlace físico de entrada. Na camada de enlace, ela realiza as funções de protocolo necessárias para interoperar com a camada de enlace do outro lado do enlace. A função mais crucial, na camada de rede, é a de busca e encaminhamento. A porta de entrada consulta a tabela de encaminhamento para determinar a porta de saída para a qual um pacote que chega deve ser direcionado. Essa tabela é mantida e atualizada pelo processador de roteamento. Uma vez determinada a porta de saída, o pacote é enviado para a estrutura de comutação.¹

**Estrutura de Comutação (Switching Fabric)**: Este componente é o coração do roteador, responsável por conectar as portas de entrada às portas de saída.²⁹ É, essencialmente, uma rede dentro do roteador. Existem vários projetos para estruturas de comutação, incluindo comutação via memória, via barramento e via uma rede de interconexão (como uma crossbar switch), que permitem que múltiplos pacotes sejam transferidos em paralelo.

**Portas de Saída**: A porta de saída armazena os pacotes que foram encaminhados a ela através da estrutura de comutação e os transmite no enlace de saída. Ela executa as funções necessárias das camadas de enlace e física, como o encapsulamento do datagrama em um quadro apropriado.¹

### 4.3.2 Formação de Fila

O enfileiramento (queuing) é uma consequência inevitável da comutação de pacotes. Como os pacotes chegam de forma assíncrona e o tráfego pode ser "em rajadas", os roteadores precisam de buffers (memória) para armazenar pacotes temporariamente. As filas podem se formar tanto nas portas de entrada quanto nas de saída.³⁰

**Enfileiramento na Saída (Output Queuing)**: Este é o cenário mais comum. Se pacotes chegam da estrutura de comutação para uma porta de saída mais rápido do que a taxa de transmissão do enlace de saída, eles precisam ser enfileirados. Se a fila crescer a ponto de exceder a capacidade do buffer, os pacotes que chegam são descartados, resultando em perda de pacotes. A disciplina de enfileiramento (como FIFO, Weighted Fair Queuing) determina a ordem em que os pacotes são transmitidos da fila.³⁰

**Enfileiramento na Entrada (Input Queuing) e Bloqueio HOL**: Para roteadores de altíssima velocidade, a estrutura de comutação pode não ser rápida o suficiente para transferir todos os pacotes que chegam para suas portas de saída sem atraso. Nesses casos, os pacotes podem ser enfileirados nas portas de entrada. Isso leva a um fenômeno de degradação de desempenho conhecido como bloqueio na cabeça da fila (Head-of-the-Line - HOL blocking). O bloqueio HOL ocorre quando um pacote em uma fila de entrada está aguardando para ser transferido para uma porta de saída que está ocupada. Esse pacote bloqueia todos os outros pacotes atrás dele na mesma fila, mesmo que as portas de saída para esses outros pacotes estejam livres. Isso limita a vazão máxima do roteador a cerca de 58.6% de sua capacidade, mesmo com padrões de tráfego uniformes.³⁰

### 4.3.3 Plano de Controle

O plano de controle é responsável pela lógica de roteamento do dispositivo. Ele executa os algoritmos de roteamento (como OSPF e BGP), se comunica com outros roteadores para trocar informações de roteamento e, com base nisso, constrói e atualiza a tabela de encaminhamento.⁶ Enquanto o plano de dados foca na velocidade de encaminhamento de pacotes individuais (uma decisão por pacote), o plano de controle opera em uma escala de tempo mais longa, lidando com a topologia da rede. A tabela de encaminhamento é a manifestação da interação entre os dois planos: o plano de controle calcula as rotas e as instala na tabela de encaminhamento para que o plano de dados possa usá-las para o repasse eficiente de pacotes.⁷

## 4.4 IP: Repasse e Endereçamento na Internet

O Protocolo da Internet (IP) é o pilar da camada de rede da Internet, definindo tanto o formato dos pacotes (datagramas) quanto o sistema de endereçamento que permite o roteamento global.

### 4.4.1 Formato do Datagrama

O datagrama IPv4 é a unidade de dados da camada de rede. Ele é composto por um cabeçalho e uma área de dados (payload) que contém o segmento da camada de transporte.³⁴ O cabeçalho IPv4 tem um tamanho mínimo de 20 bytes e contém campos cruciais para o roteamento e entrega dos pacotes.

- **Version (4 bits)**: Identifica a versão do protocolo. Para IPv4, este campo tem o valor 4 (binário 0100).³⁴
- **IHL (Internet Header Length) (4 bits)**: Especifica o comprimento do cabeçalho em palavras de 32 bits. O valor mínimo é 5 (para um cabeçalho de 20 bytes sem opções).³⁴
- **Total Length (16 bits)**: O tamanho total do datagrama (cabeçalho + dados) em bytes. O tamanho máximo de um datagrama é de 65.535 bytes.³⁴
- **TTL (Time to Live) (8 bits)**: Um contador que evita que os pacotes fiquem em loop indefinidamente na rede. Cada roteador que encaminha o pacote decrementa o valor do TTL em um. Se o TTL chegar a zero, o pacote é descartado.³⁴
- **Protocol (8 bits)**: Identifica o protocolo da camada de transporte para o qual os dados devem ser entregues no host de destino. Os valores mais comuns são 6 para TCP e 17 para UDP.

**Campos de Fragmentação**:
- **Identification (16 bits)**: Um valor único atribuído a cada datagrama pelo host de origem. Quando um datagrama é fragmentado, todos os seus fragmentos compartilham o mesmo valor de Identification, permitindo que o host de destino os reagrupe.³⁴
- **Flags (3 bits)**: Contém bits para controlar a fragmentação. O bit DF (Don't Fragment) impede que um roteador fragmente o pacote. O bit MF (More Fragments) é definido como 1 para todos os fragmentos, exceto o último.³⁴
- **Fragment Offset (13 bits)**: Especifica a posição do fragmento, em unidades de 8 bytes, em relação ao início dos dados do datagrama original. É usado pelo host de destino para remontar os fragmentos na ordem correta.³⁴

### 4.4.2 Endereçamento IPv4

O endereçamento IPv4 utiliza um endereço de 32 bits, geralmente representado em notação decimal pontuada (quatro números de 0 a 255, separados por pontos).

**Sub-redes**: Uma sub-rede é uma técnica que permite a um administrador de rede dividir uma rede grande em redes lógicas menores. Isso é feito "emprestando" bits da porção de host do endereço para criar um identificador de sub-rede. Isso melhora a organização, a segurança e a eficiência do uso de endereços.³⁷

**CIDR (Classless Inter-Domain Routing)**: O CIDR revolucionou o endereçamento IP ao abandonar o sistema rígido de classes A, B e C. Com o CIDR, a porção de rede de um endereço pode ter qualquer comprimento, indicado pela notação de prefixo (por exemplo, 192.168.1.0/24, onde /24 indica que os primeiros 24 bits são a parte da rede). O CIDR permitiu uma alocação de endereços muito mais flexível e eficiente, o que foi crucial para retardar o esgotamento dos endereços IPv4. Além disso, tornou possível a agregação de rotas (sumarização), onde múltiplos prefixos de rede contíguos podem ser anunciados como um único prefixo maior, reduzindo drasticamente o tamanho das tabelas de roteamento na Internet.³⁸

### 4.4.3 ICMP

O Protocolo de Mensagens de Controle da Internet (ICMP) é um protocolo de suporte essencial para o IP. Como o IP não fornece mecanismos para relatar erros, o ICMP é usado por hosts e roteadores para comunicar informações de controle e erro na camada de rede.⁴⁰

As mensagens ICMP mais comuns incluem:

- **Echo Request e Echo Reply**: Usadas pelo utilitário ping para testar a conectividade e medir o tempo de ida e volta (RTT) para um host de destino.⁴²
- **Destination Unreachable**: Enviada quando um roteador ou host não consegue entregar um datagrama. A mensagem inclui um código que especifica o motivo da falha (por exemplo, rede inacessível, host inacessível, porta inacessível).⁴²
- **Time Exceeded**: Enviada por um roteador quando o campo TTL de um datagrama chega a zero. Esta mensagem é a base do funcionamento do utilitário traceroute.⁴³

### 4.4.4 IPv6

O IPv6 foi desenvolvido para resolver a limitação mais crítica do IPv4: o esgotamento de seus endereços de 32 bits. Além de expandir o espaço de endereçamento, o IPv6 introduziu várias melhorias.⁴⁴

**Endereçamento de 128 bits**: A mudança mais significativa é o aumento do tamanho do endereço para 128 bits, fornecendo um número virtualmente inesgotável de endereços únicos.⁴⁴

**Formato de Cabeçalho Simplificado**: O cabeçalho base do IPv6 foi simplificado para acelerar o processamento pelos roteadores. Campos como o checksum do cabeçalho e os campos de fragmentação foram removidos do cabeçalho principal. A fragmentação, se necessária, agora é tratada apenas pelo host de origem usando um cabeçalho de extensão opcional. Isso significa que os roteadores no núcleo da rede não precisam mais realizar a tarefa computacionalmente cara de recalcular checksums ou fragmentar pacotes.⁴⁷

**Transição**: Como o IPv6 não é retrocompatível com o IPv4, a transição da Internet para o IPv6 é um processo longo e gradual. As principais estratégias de transição incluem:

- **Pilha Dupla (Dual-Stack)**: Dispositivos e roteadores executam ambos os protocolos, IPv4 e IPv6, simultaneamente e podem se comunicar usando qualquer um dos dois.⁴⁵
- **Tunelamento**: Pacotes IPv6 são encapsulados dentro de datagramas IPv4 para atravessar segmentos da Internet que ainda só suportam IPv4.⁴⁵

### 4.4.5 Segurança IP

O IPsec é um conjunto de protocolos que fornece segurança na camada de rede, protegendo todo o tráfego IP de forma transparente para as aplicações das camadas superiores.⁵⁰ Ele oferece confidencialidade, integridade e autenticação. O IPsec opera em dois modos principais:

**Modo de Transporte**: Apenas o payload (dados da camada de transporte) do pacote IP original é protegido (criptografado e/ou autenticado). O cabeçalho IP original é mantido, permitindo que o roteamento normal ocorra. Este modo é tipicamente usado para comunicações seguras de ponta a ponta entre dois hosts.⁵¹

**Modo de Túnel**: O pacote IP original inteiro (cabeçalho e payload) é encapsulado dentro de um novo pacote IP. O novo cabeçalho IP contém os endereços dos "pontos finais do túnel" (geralmente gateways de segurança ou roteadores). Este modo é a base para a criação de Redes Privadas Virtuais (VPNs), criando um "túnel" seguro através de uma rede pública como a Internet.⁵¹

## 4.5 Algoritmos de Roteamento

Os algoritmos de roteamento são o coração do plano de controle. Eles determinam o conteúdo das tabelas de encaminhamento, definindo os melhores caminhos para os pacotes viajarem pela rede. Os dois principais tipos de algoritmos de roteamento são o estado de enlace (link-state) e o vetor de distância (distance-vector).

### 4.5.1 Estado de Enlace (LS)

Os algoritmos de estado de enlace (LS) operam com a premissa de que cada roteador na rede deve ter um conhecimento completo da topologia da rede. Cada roteador constrói um "mapa" completo da rede e, em seguida, calcula de forma independente o caminho mais curto para todos os outros destinos.⁵⁴

O processo funciona em etapas:

1. **Descoberta de Vizinhos**: Cada roteador descobre os outros roteadores aos quais está diretamente conectado e mede o custo (por exemplo, atraso ou largura de banda inversa) para alcançá-los.

2. **Construção do Pacote de Estado de Enlace (LSP)**: Cada roteador cria um pequeno pacote (LSP) que contém sua identidade e os custos para seus vizinhos diretos.

3. **Inundação (Flooding) de LSPs**: O roteador transmite seu LSP para todos os outros roteadores na rede. Cada roteador que recebe um LSP o armazena e o encaminha para todos os seus vizinhos (exceto aquele de onde o recebeu). O resultado é que cada roteador rapidamente obtém uma cópia dos LSPs de todos os outros roteadores.⁵⁴

4. **Cálculo do Caminho Mais Curto**: Com um conjunto completo de LSPs, cada roteador tem um mapa idêntico da rede. Ele então usa o algoritmo de Dijkstra para calcular o caminho de menor custo de si mesmo para todos os outros roteadores. Os resultados desses cálculos são inseridos na tabela de encaminhamento.⁵⁴

Os algoritmos LS convergem rapidamente e são robustos contra loops de roteamento, mas exigem mais memória e poder de processamento nos roteadores. O OSPF é o principal protocolo que utiliza esta abordagem.

### 4.5.2 Vetor de Distância (DV)

Os algoritmos de vetor de distância (DV) são iterativos, assíncronos e distribuídos. Em vez de terem um mapa completo da rede, os roteadores conhecem apenas seus vizinhos diretos e as distâncias que esses vizinhos anunciam para outros destinos.⁵⁸ O nome "vetor de distância" vem do fato de que cada roteador mantém um vetor (uma lista) de distâncias (custos) para todos os destinos na rede.

O funcionamento é baseado na equação de Bellman-Ford: cada roteador periodicamente envia seu próprio vetor de distância para seus vizinhos. Quando um roteador recebe um vetor de um vizinho, ele atualiza sua própria tabela. Para cada destino, ele calcula um novo custo: o custo para chegar ao vizinho mais a distância que o vizinho anunciou para o destino. Se esse novo caminho for mais curto, ele atualiza sua tabela de roteamento.⁵⁹

A principal desvantagem dos algoritmos DV é o problema da contagem até o infinito. Quando um enlace falha, as "boas notícias" (uma nova rota mais curta) se propagam rapidamente, mas as "más notícias" (um enlace quebrado) se propagam lentamente. Os roteadores podem entrar em um loop, anunciando uns aos outros rotas para um destino inalcançável, incrementando a métrica (custo) a cada passo até que ela atinja um valor definido como "infinito". Para mitigar isso, são usadas técnicas como split horizon (não anunciar uma rota de volta para o roteador de onde ela foi aprendida) e route poisoning (anunciar uma rota que falhou com uma métrica infinita).⁶¹ O RIP é um exemplo clássico de protocolo DV.

### 4.5.3 Roteamento Hierárquico

Em uma rede da escala da Internet, é impraticável que todos os roteadores executem um único algoritmo de roteamento e mantenham informações sobre todas as redes existentes. As tabelas de roteamento seriam imensas e o tráfego de controle sobrecarregaria a rede.⁶³

A solução é o roteamento hierárquico, que organiza os roteadores em Sistemas Autônomos (AS). Um AS é um grupo de roteadores sob uma única administração técnica, como um provedor de internet (ISP) ou uma grande empresa.⁶⁵ O roteamento é então dividido em duas partes:

**Roteamento Intra-AS (IGP - Interior Gateway Protocol)**: Protocolos como RIP e OSPF são usados para roteamento dentro de um AS. O objetivo é encontrar o melhor caminho dentro da rede da própria organização. A topologia interna de um AS é invisível para o mundo exterior.⁶⁶

**Roteamento Inter-AS (EGP - Exterior Gateway Protocol)**: Um protocolo EGP é usado para rotear pacotes entre diferentes ASs. O BGP é o protocolo EGP padrão da Internet. Ele se concentra menos na otimização de métricas e mais na aplicação de políticas de roteamento baseadas em acordos comerciais entre os ASs.⁶⁶

Essa hierarquia permite uma escalabilidade massiva e concede autonomia administrativa a cada AS para gerenciar sua própria rede interna.

| Característica | Vetor de Distância (DV) | Estado de Enlace (LS) |
|---|---|---|
| Visão da Rede | Local (apenas vizinhos diretos) | Global (mapa completo da topologia) |
| Troca de Informação | Troca tabelas de roteamento completas | Troca informações sobre o estado dos enlaces |
| Algoritmo Base | Bellman-Ford | Dijkstra |
| Convergência | Lenta, suscetível a loops | Rápida |
| Complexidade Computacional | Baixa | Alta (cálculo de SPF) |
| Requisitos de Memória | Baixos | Altos (para armazenar o mapa da rede) |
| Problema Principal | Contagem ao Infinito | Requer sincronização do banco de dados de estado de enlace |
| Exemplos de Protocolos | RIP | OSPF, IS-IS |

## 4.6 Roteamento na Internet

Os algoritmos de roteamento discutidos anteriormente são implementados em protocolos concretos que operam na Internet. A escolha do protocolo depende do escopo (dentro de um AS ou entre ASs) e dos requisitos da rede.

### 4.6.1 RIP

O Routing Information Protocol (RIP) é um dos mais antigos protocolos de gateway interior (IGP) e é um exemplo clássico de um algoritmo de vetor de distância.⁶⁸

**Métrica**: A única métrica do RIP é a contagem de saltos (hop count), que é o número de roteadores no caminho até o destino. O caminho com menos saltos é considerado o melhor. O número máximo de saltos é 15; um destino a 16 saltos é considerado inalcançável. Isso limita severamente o tamanho das redes onde o RIP pode ser usado.⁶⁸

**Operação**: Os roteadores que executam o RIP trocam suas tabelas de roteamento completas com seus vizinhos a cada 30 segundos, usando pacotes UDP. Essas atualizações periódicas e em broadcast consomem uma quantidade considerável de largura de banda.⁷⁰

**Convergência**: O RIP é conhecido por sua convergência lenta. As "más notícias" (como a falha de um enlace) se propagam lentamente pela rede, tornando-o vulnerável ao problema da contagem ao infinito.⁶⁸

**Versões**: O RIPv1 é um protocolo classful (não envia máscaras de sub-rede nas atualizações), enquanto o RIPv2 é classless (suporta VLSM) e adiciona autenticação.⁶⁸ Devido às suas limitações, o RIP é raramente usado hoje em dias, exceto em redes muito pequenas e simples.

### 4.6.2 OSPF

O Open Shortest Path First (OSPF) é um protocolo de gateway interior (IGP) amplamente utilizado, baseado no algoritmo de estado de enlace.⁷³

**Métrica**: O OSPF usa uma métrica de custo, que por padrão é inversamente proporcional à largura de banda do enlace. Isso permite uma seleção de caminho mais inteligente do que a simples contagem de saltos do RIP.⁷⁴

**Operação**: Cada roteador OSPF constrói um mapa completo da topologia da rede (ou de sua área) e usa o algoritmo de Dijkstra para calcular os caminhos mais curtos. As atualizações de estado de enlace são enviadas apenas quando ocorrem mudanças na rede, o que é muito mais eficiente do que as atualizações periódicas do RIP.⁷⁴

**Hierarquia de Áreas**: Para garantir a escalabilidade em redes grandes, o OSPF implementa um conceito de áreas. Uma rede OSPF pode ser dividida em múltiplas áreas, e todas devem se conectar a uma área central chamada área de backbone (Área 0). O roteamento entre áreas ocorre através do backbone. Isso reduz o overhead de comunicação e o tamanho das tabelas de roteamento, pois os roteadores em uma área não precisam conhecer a topologia detalhada de outras áreas.⁷³

### 4.6.3 BGP

O Border Gateway Protocol (BGP) é o protocolo de gateway exterior (EGP) que constitui a espinha dorsal do roteamento na Internet global. Ele é responsável por trocar informações de roteamento entre os Sistemas Autônomos (ASs).⁷⁷

**Vetor de Caminho (Path Vector)**: O BGP é um protocolo de vetor de caminho. Quando um AS anuncia um prefixo de rede para um AS vizinho, ele inclui o caminho completo de ASs que a rota percorreu. Por exemplo, um anúncio para a rede X pode conter o caminho "AS2, AS1". Quando um roteador recebe este anúncio, ele sabe que para chegar à rede X, deve passar pelo AS2 e depois pelo AS1. Essa lista de ASs no caminho é usada para detectar e prevenir loops de roteamento de forma eficaz.

**Roteamento Baseado em Políticas**: A principal função do BGP não é encontrar o caminho mais curto, mas sim aplicar políticas. Os ASs (especialmente grandes ISPs) têm relações comerciais complexas (peering, trânsito). O BGP permite que os administradores de rede controlem o roteamento com base nessas políticas. Por exemplo, um AS pode preferir enviar tráfego através de um parceiro de peering (geralmente gratuito) em vez de um provedor de trânsito (pago), mesmo que o caminho de trânsito seja tecnicamente mais curto.⁷⁹ As decisões são tomadas com base em uma série de atributos BGP associados a cada rota.

## 4.7 Roteamento por Difusão e Multicast

Enquanto o roteamento unicast lida com a entrega de pacotes de uma única fonte para um único destino, o roteamento por difusão (broadcast) e multicast lidam com a entrega de um para todos e de um para muitos, respectivamente.

### 4.7.1 Algoritmos de Difusão

O objetivo do roteamento por difusão é entregar um pacote de uma fonte para todos os outros nós na rede.⁸¹

**Inundação (Flooding)**: A abordagem mais simples e óbvia. Quando um nó recebe um pacote de difusão, ele o reenvia por todas as suas interfaces, exceto aquela pela qual o pacote chegou. Sem um mecanismo de controle, isso levaria a uma "tempestade de broadcast", com pacotes duplicados circulando indefinidamente. Para controlar a inundação, são usadas técnicas como um contador de saltos (TTL) no pacote ou fazer com que cada roteador mantenha um registro dos pacotes já retransmitidos (usando um número de sequência) para evitar reenviá-los.⁸²

**Broadcast por Árvore de Extensão (Spanning Tree)**: Uma técnica muito mais eficiente que evita loops e pacotes duplicados. Primeiro, os nós da rede constroem uma árvore de extensão, que é um subgrafo que conecta todos os nós sem formar ciclos. Uma vez que a árvore está estabelecida, o nó de origem envia o pacote de difusão, e os roteadores o encaminham apenas através dos enlaces que fazem parte da árvore. Isso garante que cada nó receba exatamente uma cópia do pacote.⁸⁵

### 4.7.2 Serviço para Grupo (Multicast)

O roteamento multicast é uma forma eficiente de comunicação de "um para muitos" e "muitos para muitos". Ele permite que uma fonte envie um único pacote que é replicado pela rede apenas quando necessário para alcançar múltiplos destinos que manifestaram interesse em receber o tráfego.⁸¹ Isso é muito mais eficiente do que enviar cópias unicast separadas para cada destinatário ou usar broadcast, que envia para todos os nós, interessados ou não.

**Gerenciamento de Grupos**: Os hosts usam o Internet Group Management Protocol (IGMP) para informar a seus roteadores locais que desejam se juntar a um grupo multicast específico. Os roteadores usam essa informação para determinar para quais redes locais eles precisam encaminhar o tráfego multicast.⁸⁹

**Algoritmos de Roteamento Multicast**: Os roteadores multicast precisam construir árvores de distribuição para encaminhar os pacotes. Existem duas abordagens principais:

**Árvores por Fonte (Source-Based Trees)**: Uma árvore de caminho mais curto é construída da fonte para todos os membros do grupo. Isso resulta em caminhos ótimos em termos de latência, mas exige que os roteadores mantenham estado para cada par (fonte, grupo), o que não escala bem para um grande número de fontes. Protocolos como DVMRP e MOSPF usam essa abordagem.⁸⁸

**Árvores Compartilhadas (Shared Trees)**: Uma única árvore é compartilhada por todas as fontes para um determinado grupo. A árvore é enraizada em um ponto de encontro (Rendezvous Point - RP). As fontes enviam seu tráfego para o RP, que então o distribui pela árvore compartilhada para todos os membros. Esta abordagem é mais escalável, mas os caminhos podem não ser os mais curtos. O protocolo PIM-SM (Protocol Independent Multicast - Sparse Mode) é o protocolo de roteamento multicast mais utilizado e emprega essa técnica.⁸⁸