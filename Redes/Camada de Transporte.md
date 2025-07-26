# Relatório Técnico sobre a Camada de Transporte e Controle de Congestionamento

## 3.1 Introdução e serviços

A camada de transporte representa um pilar fundamental na arquitetura de redes de computadores, atuando como a interface entre as aplicações do usuário e a complexa infraestrutura de rede subjacente. Sua principal responsabilidade é fornecer uma comunicação lógica de ponta a ponta (end-to-end) não entre máquinas, mas entre os processos de aplicação que nelas executam.1 Enquanto a camada de rede se encarrega de entregar pacotes de um hospedeiro (host) de origem para um hospedeiro de destino, a camada de transporte refina este serviço, garantindo que os dados cheguem ao programa ou serviço correto dentro do hospedeiro de destino.3

Uma analogia eficaz para ilustrar essa distinção é a do serviço postal. A camada de rede (incorporada pelo Protocolo de Internet, ou IP) é análoga ao serviço postal que entrega uma carta a um endereço residencial específico. No entanto, uma vez que a carta chega à residência, que pode abrigar várias pessoas, é necessário um mecanismo para garantir que ela seja entregue ao destinatário correto. A camada de transporte desempenha esse papel, agindo como um membro da família que recebe a correspondência e a distribui para a pessoa específica (o processo de aplicação) a quem se destina.4

Na suíte de protocolos da Internet, esta camada é dominada por dois protocolos principais: o Protocolo de Controle de Transmissão (TCP) e o Protocolo de Datagrama do Usuário (UDP). Cada um oferece um modelo de serviço distinto, permitindo que os desenvolvedores de aplicações escolham o mecanismo de transporte mais adequado às suas necessidades, seja a confiabilidade robusta do TCP ou a velocidade e baixa sobrecarga do UDP.1

### 3.1.1 Relação com a camada de rede

A camada de transporte e a camada de rede mantêm uma relação de cliente e provedor de serviço. A camada de rede oferece um serviço de entrega de datagramas entre hospedeiros, caracterizado como "melhor esforço" (best-effort). Isso significa que o Protocolo IP não oferece garantias sobre a entrega dos pacotes, a ordem em que chegam ou sua integridade; ele simplesmente faz o melhor esforço para entregá-los.8

A camada de transporte utiliza este serviço fundamental, porém não confiável, e constrói sobre ele para fornecer serviços mais sofisticados e úteis para as aplicações. O TCP, por exemplo, implementa uma série de mecanismos complexos para criar um canal de comunicação confiável e ordenado a partir do serviço não confiável do IP. O UDP, por outro lado, estende minimamente o serviço do IP, adicionando apenas o endereçamento de processos e a verificação de erros opcional.8

Esta separação de responsabilidades é uma decisão de design arquitetural crucial para a escalabilidade e flexibilidade da Internet. A lógica da camada de transporte reside inteiramente nos sistemas finais (computadores dos usuários, servidores), enquanto a lógica da camada de rede é implementada primariamente nos roteadores que compõem o núcleo da rede. Essa distinção imuniza as aplicações das complexidades da tecnologia de rede subjacente, permitindo que desenvolvedores criem software que funcione em qualquer lugar da Internet sem precisar se preocupar com a topologia física ou os protocolos de roteamento específicos do caminho.8 Essa abstração é um dos pilares que permitiu a explosão de inovação em aplicações na Internet, pois os desenvolvedores podem contar com um conjunto padronizado de serviços de entrega (confiável ou rápido) fornecido pela camada de transporte.

### 3.1.2 Visão geral da camada

Um protocolo de camada de transporte pode, teoricamente, oferecer um espectro de serviços para as aplicações que o invocam. Os quatro serviços principais são 10:

**Transferência Confiável de Dados:** Este é talvez o serviço mais crítico. Um protocolo que oferece transferência confiável de dados garante que o fluxo de bytes enviado por uma aplicação chegue ao seu destino de forma completa, sem erros e na ordem correta. A aplicação pode, assim, entregar dados ao seu socket de transporte com a certeza de que serão recebidos intactos pelo processo de destino.10 O TCP é o principal protocolo da Internet que implementa este serviço.6

**Vazão (Throughput):** Algumas aplicações, conhecidas como sensíveis à largura de banda, necessitam de uma taxa de transmissão mínima garantida para funcionar corretamente. Um protocolo de transporte poderia oferecer garantias de vazão, assegurando que uma aplicação receba, por exemplo, pelo menos 1 Mbps de largura de banda. Aplicações elásticas, como e-mail ou transferência de arquivos, por outro lado, podem funcionar com qualquer vazão disponível, utilizando mais quando possível e menos quando necessário.10

**Temporização (Timing):** Aplicações em tempo real, como telefonia pela Internet (VoIP), jogos online e videoconferências, são altamente sensíveis a atrasos. Um serviço de temporização garantiria que cada segmento de dados chegue ao destino dentro de um limite de tempo máximo, por exemplo, 100 ms. Isso é crucial para manter a interatividade e a qualidade da experiência do usuário.10

**Segurança:** A camada de transporte pode incorporar serviços de segurança. Isso inclui a confidencialidade, através da criptografia dos dados do segmento para protegê-los de interceptação; a integridade dos dados, para garantir que não sejam alterados em trânsito; e a autenticação de ponta a ponta, para que ambos os processos possam verificar a identidade um do outro.10

É fundamental notar que os protocolos de transporte padrão da Internet, TCP e UDP, não fornecem todos esses serviços nativamente. O TCP oferece transferência de dados confiável e, através de seus mecanismos de controle, tenta maximizar a vazão de forma justa, mas não pode garantir um valor mínimo. O UDP não oferece garantias de confiabilidade, vazão ou temporização. Serviços como garantias de temporização e segurança são tipicamente implementados em camadas superiores ou por protocolos adicionais, como o Transport Layer Security (TLS), que opera sobre o TCP para fornecer segurança.

## 3.2 Multiplexação e demultiplexação

Em um sistema final moderno, é comum que múltiplos processos de rede estejam em execução simultaneamente. Um usuário pode estar navegando na web, recebendo e-mails e participando de uma videoconferência ao mesmo tempo. Isso apresenta um desafio fundamental: quando um segmento de dados chega da camada de rede, como o sistema operacional sabe para qual processo de aplicação específico ele deve ser entregue? A solução para este problema reside nas funções de multiplexação e demultiplexação da camada de transporte.12

A entrega de dados ao processo correto é viabilizada pelo uso de portas. Cada segmento de transporte inclui campos para a porta de origem e a porta de destino. As portas são números de 16 bits, variando de 0 a 65535, que servem como identificadores para os processos em um hospedeiro.12 A combinação de um endereço IP e um número de porta constitui um socket, que funciona como o ponto final único de uma comunicação processo-a-processo.3

A multiplexação, no hospedeiro de origem, é o processo de coletar dados de múltiplos sockets, adicionar os cabeçalhos da camada de transporte (que incluem as portas de origem e destino) para criar segmentos, e então passar esses segmentos para a camada de rede para transmissão.3 Por outro lado, a demultiplexação, no hospedeiro de destino, é o processo inverso: receber os segmentos da camada de rede, examinar os campos de porta no cabeçalho para identificar o socket de destino correto e entregar o segmento a esse socket.3

A forma como a demultiplexação é realizada difere entre UDP e TCP:

**Demultiplexação sem Conexão (UDP):** Um socket UDP é unicamente identificado por uma tupla de dois valores: o endereço IP de destino e a porta de destino. Quando um segmento UDP chega, o hospedeiro examina esses dois campos e o direciona para o socket correspondente. Uma consequência disso é que múltiplos segmentos UDP de diferentes emissores (com diferentes IPs e portas de origem) podem ser direcionados para o mesmo socket de destino, desde que compartilhem o mesmo IP e porta de destino.5

**Demultiplexação Orientada a Conexão (TCP):** Um socket TCP é identificado por uma tupla de quatro valores: endereço IP de origem, porta de origem, endereço IP de destino e porta de destino. Quando um segmento TCP chega, o hospedeiro utiliza todos os quatro valores para determinar o socket correto. Isso permite que um único processo servidor (por exemplo, um servidor web na porta 80) mantenha múltiplas conexões simultâneas com diferentes clientes. Cada conexão é um socket único e distinto, pois, embora o IP e a porta de destino sejam os mesmos, a combinação de IP e porta de origem de cada cliente será diferente.5

A multiplexação e a demultiplexação são os mecanismos que viabilizam a experiência multitarefa na Internet como a conhecemos. Sem eles, um computador com uma única conexão de rede só poderia executar uma aplicação de rede por vez. Ao "carimbar" cada segmento com identificadores de processo (portas), a camada de transporte permite que uma única interface de rede física seja compartilhada por um número virtualmente ilimitado de aplicações, transformando um único hospedeiro em múltiplos pontos de comunicação virtuais.

## 3.3 Transporte não orientado para conexão: UDP

O Protocolo de Datagrama do Usuário (UDP) representa a abordagem mais minimalista para o transporte de dados na Internet. É um protocolo leve, "sem luxos", que estende o serviço de "melhor esforço" da camada IP para a comunicação entre processos.4 O UDP é um protocolo sem conexão, o que significa que não há um procedimento de estabelecimento de conexão (handshake) antes do envio de dados. Cada segmento UDP, chamado de datagrama, é tratado de forma independente.14

A principal característica do UDP é sua falta de garantias. Ele não assegura que os datagramas chegarão ao destino, nem que chegarão na ordem em que foram enviados. A confiabilidade, se necessária, deve ser implementada pela própria aplicação.4 Essa simplicidade, no entanto, é sua maior força, resultando em baixa sobrecarga e baixa latência. Por essa razão, o UDP é a escolha preferencial para aplicações sensíveis ao tempo, onde a velocidade supera a necessidade de confiabilidade absoluta. Exemplos incluem streaming de mídia ao vivo, telefonia VoIP, jogos online e o Sistema de Nomes de Domínio (DNS), aplicações que podem tolerar a perda de alguns pacotes sem uma degradação catastrófica da experiência do usuário.15

### 3.3.1 Estrutura do segmento

A simplicidade do UDP é refletida em sua estrutura de segmento. O cabeçalho UDP tem um tamanho fixo e mínimo de apenas 8 bytes, composto por quatro campos de 16 bits cada 13:

**Porta de Origem (16 bits):** Identifica a porta do processo no hospedeiro emissor. Este campo é opcional e, se não for utilizado, é preenchido com zeros. Sua principal função é permitir que o receptor saiba para onde enviar uma resposta.13

**Porta de Destino (16 bits):** Identifica o processo de aplicação no hospedeiro receptor. Este campo é obrigatório.

**Comprimento (16 bits):** Especifica o comprimento total do datagrama UDP em bytes, incluindo o cabeçalho de 8 bytes e os dados da aplicação.

**Soma de Verificação (Checksum - 16 bits):** Utilizado para a detecção de erros.

### 3.3.2 Soma de verificação

O campo de soma de verificação (checksum) do UDP oferece um mecanismo para detectar erros, como bits invertidos, que possam ter ocorrido durante a transmissão do segmento através da rede.13

O processo de cálculo funciona da seguinte maneira:

**No Emissor:** O emissor trata o conteúdo do segmento UDP (cabeçalho e dados), juntamente com um "pseudo-cabeçalho" contendo os endereços IP de origem e destino, o número do protocolo (UDP) e o comprimento do UDP, como uma sequência de palavras de 16 bits.

Essas palavras são somadas utilizando a aritmética de complemento de um.

O complemento de um do resultado final é inserido no campo de checksum do cabeçalho UDP.13

**No Receptor:** O receptor realiza exatamente o mesmo cálculo sobre os dados recebidos. Ele soma todas as palavras de 16 bits (incluindo o campo de checksum recebido). Se não houveram erros, o resultado da soma no receptor será uma sequência de todos os bits 1. Se um ou mais bits forem 0, isso indica que um erro foi detectado.13

Quando um erro é detectado, a ação subsequente depende da implementação. O segmento pode ser simplesmente descartado ou pode ser passado para a camada de aplicação com um aviso de que os dados estão corrompidos.13 É crucial notar que o uso do checksum no UDP é opcional. Se o emissor preencher o campo de checksum com zeros, isso sinaliza ao receptor que nenhuma verificação de erro foi realizada.13

A natureza opcional do checksum e a ausência de mecanismos de correção de erros reforçam a filosofia do UDP: fornecer um serviço de transporte rápido e com baixa sobrecarga, delegando a complexidade do controle de erros e da confiabilidade para a camada de aplicação, que pode então implementar estratégias mais adequadas às suas necessidades específicas.

## 3.4 Princípios da transferência confiável de dados

Um dos desafios mais fundamentais em redes de computadores é como construir um canal de comunicação confiável sobre um meio que é inerentemente não confiável. A camada de rede subjacente pode corromper bits em um pacote ou perder pacotes inteiros. A tarefa de um protocolo de transferência de dados confiável (RDT, do inglês Reliable Data Transfer) é garantir que, apesar dessas falhas, os dados sejam entregues da camada de aplicação do emissor para a do receptor de forma correta e na ordem certa. Os princípios desenvolvidos aqui formam a base para protocolos como o TCP.11

A construção de um protocolo RDT pode ser entendida através de uma evolução incremental, começando com suposições simples e adicionando complexidade para lidar com cenários do mundo real.

### 3.4.1 Protocolo simples

A abordagem mais básica para a transferência de dados é o modelo de parada e espera (stop-and-wait).

**RDT 1.0 (Canal Confiável):** Na suposição ideal de um canal perfeitamente confiável, o protocolo é trivial: o emissor simplesmente envia os dados para o canal, e o receptor os retira do canal.11

**RDT 2.0 (Canal com Erros de Bits):** Introduzindo a possibilidade de erros de bits, o protocolo precisa de feedback do receptor. Isso é alcançado através de confirmações positivas (ACKs) e confirmações negativas (NAKs). O receptor envia um ACK se o pacote é recebido corretamente e um NAK se está corrompido. O emissor retransmite o último pacote ao receber um NAK e espera pelo próximo dado da camada de aplicação ao receber um ACK.

**RDT 2.1 e 2.2 (Lidando com ACKs/NAKs Corrompidos):** O próprio feedback pode ser corrompido. Para resolver isso, são introduzidos números de sequência. O emissor numera os pacotes de dados (alternando entre 0 e 1, no caso mais simples). Se o receptor recebe um pacote duplicado (indicado pelo número de sequência), ele sabe que seu último ACK/NAK foi perdido ou corrompido e simplesmente reenvia a última confirmação. A versão RDT 2.2 elimina a necessidade de NAKs, usando ACKs para o último pacote recebido corretamente. Se o emissor recebe um ACK duplicado, ele entende que o pacote subsequente foi perdido ou corrompido e o retransmite.18

**RDT 3.0 (Canal com Erros e Perdas):** A última falha a ser tratada é a perda de pacotes (tanto de dados quanto de ACKs). O emissor agora precisa de um mecanismo para detectar essa perda. A solução é um temporizador de contagem regressiva. O emissor inicia um temporizador sempre que envia um pacote. Se o temporizador expirar antes de um ACK correspondente ser recebido, o emissor assume que o pacote foi perdido e o retransmite.18 A combinação de checksums, números de sequência, ACKs e temporizadores permite a transferência confiável sobre um canal não confiável.

### 3.4.2 Protocolos com paralelismo

O desempenho do protocolo de parada e espera é severamente limitado, pois o emissor só pode ter um único pacote em trânsito por vez. Em redes com alto produto de largura de banda e atraso, isso leva a uma utilização muito baixa do canal. Para superar essa limitação, são utilizados protocolos com paralelismo (pipelining), que permitem ao emissor enviar múltiplos pacotes sem esperar pela confirmação de cada um, mantendo vários pacotes "em voo" simultaneamente.20 Isso requer números de sequência maiores e o armazenamento em buffer de pacotes no emissor e, possivelmente, no receptor. Dois dos principais protocolos de paralelismo são o Go-Back-N e a Repetição Seletiva.

### 3.4.3 Go-Back-N (GBN)

O protocolo Go-Back-N permite que o emissor transmita múltiplos pacotes (até um máximo definido pelo tamanho da janela, N) antes de receber uma confirmação, mas com uma abordagem simples para o receptor.21

**Funcionamento do Emissor:** O emissor mantém uma janela de até N números de sequência consecutivos permitidos para pacotes não confirmados. Conforme os ACKs chegam, a janela desliza para frente, permitindo o envio de novos pacotes. Um único temporizador é mantido para o pacote mais antigo não confirmado.21

**Funcionamento do Receptor:** A simplicidade do GBN reside no receptor. Ele mantém apenas um estado: o número de sequência do próximo pacote que espera receber em ordem (expectedseqnum). Se um pacote com esse número de sequência chega sem erros, ele é entregue à camada superior, expectedseqnum é incrementado, e um ACK cumulativo é enviado. Este ACK confirma a recepção de todos os pacotes até aquele número de sequência.21 Se um pacote chega fora de ordem (ou seja, com um número de sequência diferente de expectedseqnum), ele é simplesmente descartado.

**Recuperação de Erro:** Se o temporizador do pacote mais antigo expira, o emissor assume que este pacote (e possivelmente os subsequentes) se perdeu. Ele então retransmite todos os pacotes na janela que ainda não foram confirmados, começando pelo pacote cujo temporizador expirou. Essa abordagem "volta N" pacotes, daí o nome do protocolo.23

### 3.4.4 Repetição seletiva (SR)

O protocolo de Repetição Seletiva (SR) aprimora o GBN ao evitar retransmissões desnecessárias, o que é particularmente benéfico em redes com altas taxas de perda de pacotes.20

**Funcionamento do Emissor:** Assim como no GBN, o emissor mantém uma janela de N pacotes não confirmados. No entanto, cada pacote na janela tem seu próprio temporizador lógico.

**Funcionamento do Receptor:** O receptor confirma individualmente cada pacote recebido corretamente, independentemente de sua ordem.26 Pacotes que chegam fora de ordem são armazenados em um buffer. Quando um pacote chega e preenche uma lacuna na sequência, um bloco contíguo de pacotes em buffer pode ser entregue à camada de aplicação. A janela de recepção desliza para frente para o próximo pacote ainda não recebido.19

**Recuperação de Erro:** O emissor retransmite apenas os pacotes para os quais suspeita de perda, ou seja, aqueles cujos temporizadores expiram. Isso significa que apenas os pacotes individuais perdidos são reenviados, em vez de um bloco inteiro de pacotes como no GBN.

A distinção entre GBN e SR ilustra um clássico trade-off de engenharia. O GBN simplifica a lógica do receptor (que não precisa de buffer para pacotes fora de ordem), mas pode ser ineficiente ao retransmitir pacotes que já foram recebidos com sucesso. O SR otimiza o uso da largura de banda com retransmissões mais precisas, mas exige uma lógica mais complexa e gerenciamento de buffer no receptor.

| Característica | Go-Back-N (GBN) | Repetição Seletiva (SR) |
|---|---|---|
| Janela de Recepção | Tamanho 1 | Tamanho N |
| Confirmação (ACK) | Cumulativa (confirma todos os pacotes até N) | Individual (confirma cada pacote separadamente) |
| Buffering no Receptor | Não armazena pacotes fora de ordem | Armazena pacotes fora de ordem |
| Retransmissão | Retransmite o pacote perdido e todos os subsequentes | Retransmite apenas o pacote perdido |
| Complexidade do Receptor | Simples | Complexa |

## 3.5 Transporte orientado para conexão: TCP

O Protocolo de Controle de Transmissão (TCP) é o principal protocolo de transporte orientado a conexão da Internet, projetado para fornecer um serviço de transferência de dados confiável e ordenado sobre a camada de rede IP, que é inerentemente não confiável. É a base para muitas das aplicações mais populares da Internet, incluindo a World Wide Web (HTTP), e-mail (SMTP) e transferência de arquivos (FTP).1 O TCP incorpora os princípios de transferência confiável de dados, como números de sequência e confirmações, e adiciona mecanismos sofisticados para controle de fluxo e controle de congestionamento.4

### 3.5.1 A conexão TCP

Diferentemente do UDP, o TCP é orientado a conexão. Isso significa que antes que os processos de aplicação possam começar a trocar dados, eles devem primeiro estabelecer uma conexão um com o outro. Essa conexão é uma construção lógica, mantida por variáveis de estado em ambos os sistemas finais, e não implica em nenhum circuito físico sendo alocado nos roteadores da rede.

O estabelecimento da conexão é realizado através de um processo conhecido como three-way handshake (aperto de mão de três vias) 29:

1. **SYN:** O cliente inicia o processo enviando um segmento TCP especial ao servidor. Este segmento tem o bit de controle SYN (de synchronize) ativado e contém um número de sequência inicial (client_isn) escolhido aleatoriamente pelo cliente.

2. **SYN-ACK:** Ao receber o segmento SYN, o servidor aloca buffers e variáveis para a conexão. Em seguida, ele responde com seu próprio segmento especial. Este segmento tem os bits SYN e ACK (de acknowledgment) ativados, contém um número de sequência inicial escolhido pelo servidor (server_isn) e, no campo de número de confirmação, coloca o valor client_isn + 1.

3. **ACK:** Ao receber o segmento SYN-ACK, o cliente aloca seus próprios buffers e variáveis. Ele então envia um último segmento para o servidor para confirmar a conexão. Este segmento tem o bit ACK ativado e o número de confirmação é definido como server_isn + 1.

Após a conclusão dessas três etapas, a conexão TCP está estabelecida e os dados da aplicação podem ser trocados em ambas as direções (full-duplex).31

### 3.5.2 Estrutura do segmento

Cada unidade de dados TCP é chamada de segmento. Um segmento TCP consiste em um cabeçalho seguido pelos dados da aplicação. O cabeçalho, que tem um tamanho base de 20 bytes (podendo ser maior se houver opções), contém campos essenciais para o funcionamento do protocolo 30:

**Porta de Origem e Porta de Destino (16 bits cada):** Usadas para a multiplexação e demultiplexação, identificando os processos de aplicação nos hospedeiros de origem e destino.

**Número de Sequência (32 bits):** Identifica a posição do primeiro byte de dados neste segmento dentro do fluxo de bytes geral da conexão. O TCP enxerga o fluxo de dados como uma sequência contínua de bytes, e este campo é crucial para garantir a entrega ordenada e detectar pacotes perdidos.34

**Número de Confirmação (32 bits):** Quando o bit ACK está ativado, este campo contém o número de sequência do próximo byte que o receptor espera receber. O TCP usa confirmações cumulativas; um ACK para o byte N confirma que todos os bytes até N−1 foram recebidos corretamente.34

**Comprimento do Cabeçalho (HLEN, 4 bits):** Especifica o comprimento do cabeçalho TCP em palavras de 32 bits. É necessário porque o campo de opções pode ter tamanho variável.

**Flags de Controle (9 bits):** Bits únicos que governam a conexão. Os mais importantes são:
- **SYN:** Usado para iniciar uma conexão.
- **ACK:** Indica que o campo de número de confirmação é válido.
- **RST:** Reseta a conexão.
- **PSH:** Indica ao receptor para passar os dados para a camada de aplicação imediatamente.
- **FIN:** Usado para encerrar uma conexão.
- **URG:** Indica que o ponteiro de urgência é válido.33

**Janela de Recepção (16 bits):** Usado para controle de fluxo. Especifica o número de bytes que o receptor está atualmente disposto a aceitar.33

**Soma de Verificação (16 bits):** Usado para detecção de erros no cabeçalho e nos dados do segmento, de forma similar ao UDP.

**Ponteiro de Urgência (16 bits):** Quando o flag URG está ativado, este campo aponta para o último byte de dados urgentes no segmento.

**Opções (comprimento variável):** Permite funcionalidades adicionais, como a negociação do Tamanho Máximo do Segmento (MSS) durante o handshake.32

### 3.5.3 Estimativa de RTT e timeout

Para garantir a entrega confiável, o TCP utiliza um temporizador para retransmitir segmentos que não foram confirmados. O valor deste temporizador de retransmissão (RTO) é um parâmetro crítico de desempenho. Se for muito curto, ocorrerão retransmissões desnecessárias, sobrecarregando a rede. Se for muito longo, a recuperação de perdas será lenta.37

O desafio é que o tempo de ida e volta (RTT) em uma conexão na Internet é altamente dinâmico e imprevisível. Para lidar com isso, o TCP mede continuamente o RTT e ajusta o RTO de forma adaptativa. Ele não usa apenas a medição mais recente (SampleRTT), mas calcula uma média móvel ponderada exponencialmente (EstimatedRTT) para suavizar as flutuações 38:

```
EstimatedRTT = (1−α) ⋅ EstimatedRTT + α ⋅ SampleRTT
```

Onde α é um fator de ponderação, tipicamente 0.125.

Além disso, para criar uma margem de segurança, o TCP também calcula a variação do RTT (DevRTT), que é uma estimativa do desvio padrão do RTT 38:

```
DevRTT = (1−β) ⋅ DevRTT + β ⋅ |SampleRTT − EstimatedRTT|
```

Onde β é tipicamente 0.25. O valor final do RTO é então calculado combinando a média e a variação, fornecendo uma margem de segurança robusta 39:

```
RTO = EstimatedRTT + 4 ⋅ DevRTT
```

Este mecanismo adaptativo é um dos segredos do sucesso do TCP, permitindo que ele opere eficientemente em uma vasta gama de condições de rede, desde LANs de baixa latência até conexões de satélite de alta latência.

### 3.5.4 Transferência confiável

O mecanismo de transferência confiável do TCP é uma implementação sofisticada dos princípios de RDT. Ele utiliza um único temporizador de retransmissão associado ao segmento mais antigo não confirmado. A retransmissão de um segmento perdido é acionada por dois eventos distintos:

**Esgotamento do Temporizador (Timeout):** Se o RTO para o segmento mais antigo não confirmado expirar, o TCP assume que o segmento foi perdido e o retransmite.39 Este é o mecanismo de recuperação de falhas mais básico.

**Três ACKs Duplicados (Fast Retransmit):** Uma otimização crucial é o mecanismo de Fast Retransmit. Quando um receptor recebe um segmento com um número de sequência maior do que o esperado (indicando uma lacuna), ele começa a gerar ACKs duplicados para o último byte em ordem que recebeu. Se o emissor receber três desses ACKs duplicados, ele infere que o segmento que se segue ao byte confirmado foi perdido e o retransmite imediatamente, sem esperar que o temporizador expire. Isso acelera significativamente a recuperação de perdas isoladas de pacotes, que são comuns na Internet.40

### 3.5.5 Controle de fluxo

O controle de fluxo é um serviço essencial que impede que o emissor envie dados mais rápido do que o receptor consegue processá-los, evitando assim o transbordamento (overflow) do buffer de recepção.42

O TCP implementa o controle de fluxo usando um mecanismo de janela deslizante. O receptor anuncia o espaço disponível em seu buffer de recepção (conhecido como rwnd, ou receive window) no campo "Janela de Recepção" de cada segmento que envia de volta ao emissor.43 O emissor, por sua vez, deve garantir que a quantidade de dados enviados mas ainda não confirmados (LastByteSent - LastByteAcked) não exceda o valor de rwnd anunciado pelo receptor.44 À medida que o receptor processa os dados e libera espaço no buffer, ele anuncia um rwnd maior, fazendo com que a janela "deslize" para frente e permitindo que o emissor envie mais dados.46

É importante distinguir o controle de fluxo do controle de congestionamento. O controle de fluxo protege o receptor de ser sobrecarregado, enquanto o controle de congestionamento (discutido na seção 3.7) protege a rede de ser sobrecarregada. A taxa de envio real do TCP é, portanto, o mínimo entre a janela de recepção (rwnd) e a janela de congestionamento (cwnd).

### 3.5.6 Gerenciamento da conexão

Assim como o estabelecimento, o encerramento de uma conexão TCP é um processo ordenado. Como as conexões TCP são full-duplex, cada direção do fluxo de dados deve ser encerrada independentemente. Isso geralmente resulta em um processo de quatro etapas 29:

1. Um dos lados (geralmente o cliente) decide encerrar a conexão e envia um segmento com o bit FIN ativado.

2. O outro lado (servidor) recebe o FIN e envia um ACK para confirmá-lo. Neste ponto, a conexão está "semi-fechada": o servidor não receberá mais dados do cliente, mas ainda pode enviar dados para ele.

3. Quando o servidor também termina de enviar seus dados, ele envia seu próprio segmento FIN.

4. O cliente recebe o FIN do servidor e responde com um ACK. Após um período de espera para garantir que o ACK final não foi perdido, ambos os lados liberam os recursos da conexão.

## 3.6 Controle de congestionamento

O controle de congestionamento é um mecanismo vital para a estabilidade e eficiência da Internet. Ele visa prevenir ou mitigar a condição em que a demanda por recursos de rede excede a capacidade disponível, levando a uma degradação severa do desempenho.

### 3.6.1 Causas e custos

O congestionamento de rede ocorre quando os pacotes chegam a um link ou roteador a uma taxa maior do que a capacidade de processamento ou encaminhamento desse recurso.48 As consequências do congestionamento são multifacetadas e representam custos significativos para a rede:

**Aumento do Atraso de Fila:** À medida que a taxa de chegada de pacotes a um roteador se aproxima da capacidade de seu link de saída, os pacotes começam a se acumular nos buffers (filas), resultando em longos atrasos de enfileiramento para todos os pacotes que passam por aquele link.50

**Perda de Pacotes:** Os buffers dos roteadores têm capacidade finita. Quando um buffer fica cheio, os pacotes que chegam subsequentemente são descartados. Essa perda de pacotes é o sinal mais claro de congestionamento.52

**Retransmissões Desnecessárias:** Quando um protocolo de transporte confiável como o TCP detecta a perda de um pacote, ele o retransmite. Essas retransmissões consomem largura de banda que poderia ser usada para transmitir novos dados, adicionando mais carga a uma rede já congestionada e reduzindo a vazão útil (goodput).50

**Desperdício de Recursos "Rio Acima":** Quando um pacote é descartado em um roteador congestionado, todo o trabalho de transmissão realizado pelos roteadores e links anteriores ("rio acima") no caminho até aquele ponto é desperdiçado. Esse custo se agrava em caminhos com múltiplos saltos.50

Sem mecanismos de controle, esses efeitos podem levar a um fenômeno conhecido como colapso congestivo, onde a vazão útil da rede cai para perto de zero, mesmo com um alto volume de tráfego sendo injetado.

### 3.6.2 Mecanismos de controle

Existem duas abordagens filosóficas para o controle de congestionamento:

**Controle de Congestionamento Fim a Fim (End-to-End):** Nesta abordagem, a camada de rede não fornece nenhum feedback explícito sobre o congestionamento. Os sistemas finais (emissores e receptores) devem inferir a presença de congestionamento observando o comportamento da rede, como a perda de pacotes (detectada por timeouts ou confirmações duplicadas) e o aumento do RTT. O TCP é o principal exemplo de um protocolo que utiliza essa abordagem.50

**Controle de Congestionamento Assistido pela Rede:** Nesta abordagem, os roteadores participam ativamente do processo, fornecendo feedback explícito aos sistemas finais. Este feedback pode assumir várias formas 54:

- **Notificação Explícita:** Um roteador pode marcar um bit em um pacote (como no ECN - Explicit Congestion Notification) para sinalizar que está começando a ficar congestionado.54
- **Taxa Explícita:** Um roteador pode informar diretamente ao emissor qual a taxa de transmissão máxima que ele pode suportar naquele momento.54

### 3.6.3 Exemplo: ATM ABR

O serviço de Taxa de Bits Disponível (ABR - Available Bit Rate) nas redes de Modo de Transferência Assíncrona (ATM) é um exemplo clássico de controle de congestionamento assistido pela rede, utilizando uma abordagem baseada em taxa.54

O mecanismo funciona da seguinte forma:

1. A fonte de dados envia periodicamente células especiais de gerenciamento de recursos (RM-cells) intercaladas com as células de dados.

2. Essas RM-cells viajam pelo mesmo caminho que os dados até o destino. Ao longo do caminho, cada switch (roteador ATM) examina a RM-cell e, se estiver congestionado, pode modificá-la para fornecer feedback.56

3. O destino retorna a RM-cell para a fonte, que então ajusta sua taxa de transmissão com base no feedback recebido.

O feedback pode ser fornecido de três maneiras:

- **Bit EFCI:** Switches podem marcar um bit em células de dados para indicar congestionamento, que o destino então copia para a RM-cell de retorno.
- **Bits CI e NI:** Switches podem definir diretamente os bits de Indicação de Congestionamento (CI) ou de Não Aumento (NI) na RM-cell de retorno.
- **Taxa Explícita (ER):** O mecanismo mais sofisticado, onde cada switch pode reduzir o valor do campo de Taxa Explícita (ER) na RM-cell para a taxa que ele pode suportar. A fonte receberá o valor mínimo de ER de todos os switches no caminho e ajustará sua taxa para esse valor.56

## 3.7 Controle de congestionamento no TCP

O TCP adota uma abordagem de controle de congestionamento fim a fim, onde cada emissor regula sua taxa de transmissão com base em sua percepção do estado da rede. Ele não recebe ajuda explícita dos roteadores. Em vez disso, infere o congestionamento principalmente através da perda de pacotes.56

A taxa de envio do TCP é limitada por uma variável de estado chamada janela de congestionamento (cwnd). A quantidade de dados não confirmados que um emissor pode ter na rede é o mínimo entre a cwnd e a janela de recepção do receptor (rwnd). A taxa de envio pode ser aproximada por cwnd/RTT. Ao ajustar o valor de cwnd, o TCP ajusta sua taxa de envio.59

O algoritmo de controle de congestionamento do TCP é uma combinação de três mecanismos principais, conforme definido na RFC 5681 60:

**Partida Lenta (Slow Start):** Quando uma conexão TCP começa, o valor de cwnd é inicializado com um valor pequeno, tipicamente 1 MSS (Maximum Segment Size). Para cada ACK recebido, o cwnd é incrementado em 1 MSS. Isso resulta em um crescimento exponencial da janela de congestionamento (ela dobra aproximadamente a cada RTT). O objetivo da partida lenta é encontrar rapidamente a capacidade disponível na rede sem inundá-la desde o início.38

**Prevenção de Congestionamento (Congestion Avoidance):** O crescimento exponencial da partida lenta não pode continuar indefinidamente. Quando o cwnd atinge um valor de limiar chamado ssthresh (slow start threshold), o TCP entra no modo de prevenção de congestionamento. Nesta fase, o crescimento do cwnd torna-se muito mais cauteloso e linear. Para cada RTT em que não há perdas, o cwnd é incrementado em apenas 1 MSS. Este aumento aditivo permite que o TCP sonde lentamente por largura de banda adicional.59

**Reação a Eventos de Perda (Fast Retransmit e Fast Recovery):** A forma como o TCP reage a uma perda de pacote é o cerne de seu mecanismo.

- **Perda por Timeout:** Se um temporizador expira, o TCP interpreta isso como um sinal de congestionamento severo. Ele reage de forma agressiva: o ssthresh é definido para metade do valor atual do cwnd, e o cwnd é resetado para 1 MSS. A conexão então reentra na fase de Partida Lenta.59

- **Perda por 3 ACKs Duplicados:** Se o emissor recebe três ACKs duplicados, ele executa o Fast Retransmit (retransmissão rápida) do segmento perdido sem esperar pelo timeout. Em seguida, em vez de retornar à partida lenta, ele entra em Fast Recovery (recuperação rápida). O ssthresh é definido para metade do cwnd, e o cwnd é também definido para este novo valor de ssthresh (diminuição multiplicativa). A partir daí, a conexão entra diretamente na fase de Prevenção de Congestionamento, continuando com o crescimento linear. Isso permite uma recuperação muito mais rápida do que um timeout.59

Essa estratégia de aumentar a janela linearmente e reduzi-la pela metade em resposta à perda é conhecida como AIMD (Additive Increase, Multiplicative Decrease) e é fundamental para a estabilidade do TCP.59

### 3.7.1 Equidade

Um objetivo desejável para um protocolo de controle de congestionamento é a equidade. Idealmente, se K conexões TCP compartilham um link gargalo com uma capacidade total de R bps, cada conexão deveria obter uma taxa média de R/K bps.64

O algoritmo AIMD do TCP converge para uma alocação justa da largura de banda. Considere duas conexões TCP compartilhando um link. A soma de suas taxas de transmissão é limitada pela capacidade R. Em um gráfico onde os eixos representam as taxas das duas conexões, o estado ideal de operação está na linha de equidade. O mecanismo AIMD faz com que as taxas das conexões oscilem em torno dessa linha. Quando a soma das taxas excede a capacidade, uma das conexões (provavelmente a que tem a maior taxa) sofrerá uma perda e reduzirá sua janela pela metade (um movimento em direção à origem do gráfico). Enquanto isso, a outra conexão continua a aumentar sua taxa linearmente (um movimento para longe da origem). Esse comportamento de "serra" empurra as conexões para um ponto de operação onde elas compartilham a largura de banda de forma equitativa ao longo do tempo.53

Este comportamento é um exemplo de como um sistema descentralizado e distribuído, onde cada agente (conexão TCP) segue um algoritmo simples e egoísta (tentar aumentar a taxa até que a perda ocorra), pode levar a um resultado globalmente eficiente e justo. É essa inteligência emergente que permite que milhões de conexões TCP coexistam e compartilhem a infraestrutura da Internet de forma estável.