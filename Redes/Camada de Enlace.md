# Análise Aprofundada de Protocolos da Camada de Enlace e Arquiteturas de Rede

## 5.1 Introdução à Camada de Enlace

A camada de enlace de dados, ou Camada 2 no modelo de referência OSI (Open Systems Interconnection), constitui um elo fundamental na arquitetura de redes de computadores, posicionando-se entre a camada física (Camada 1) e a camada de rede (Camada 3).¹ Sua responsabilidade primordial é gerenciar a transferência de dados através de um único enlace de comunicação, conectando nós adjacentes na rede. Esses nós podem ser computadores, roteadores ou outros dispositivos de rede, e a conexão entre eles pode ser um enlace ponto a ponto ou um meio de transmissão compartilhado (broadcast).³ A unidade de dados de protocolo (PDU) nesta camada é denominada quadro (frame), que encapsula o datagrama recebido da camada de rede para prepará-lo para a transmissão física.³

Para contextualizar o papel da camada de enlace, pode-se recorrer a uma analogia com um sistema de transporte multimodal. Se um datagrama da camada de rede for análogo a um turista que deseja viajar de uma cidade de origem a um destino final, o algoritmo de roteamento da camada de rede atua como o agente de viagens que planeja toda a rota, decidindo quais cidades intermediárias e conexões serão utilizadas. Cada trecho dessa viagem — como um táxi do ponto inicial a um aeroporto, um voo entre aeroportos e um trem até o destino final — representa um enlace de comunicação individual. O modo de transporte específico para cada trecho, com suas regras, veículo e tipo de bilhete, é o protocolo da camada de enlace.³ Assim, a camada de enlace se concentra na logística de mover o "turista" (datagrama) de forma confiável e eficiente através de um único segmento da jornada, enquanto a camada de rede se preocupa com o planejamento da rota completa, de ponta a ponta.

### 5.1.1 Serviços fornecidos

A camada de enlace de dados é projetada para oferecer um conjunto de serviços essenciais à camada de rede, garantindo que os datagramas possam ser movidos de forma eficaz entre nós adjacentes. Embora a implementação específica varie entre diferentes protocolos de enlace, as funcionalidades centrais são consistentes.⁶

#### Enquadramento (Framing)

O serviço mais fundamental da camada de enlace é o enquadramento. Este processo consiste em pegar os datagramas da camada de rede e encapsulá-los em quadros. O enquadramento adiciona um cabeçalho e, frequentemente, um trailer ao datagrama. O cabeçalho contém informações de controle, como os endereços físicos (endereços MAC) do nó de origem e de destino, que são cruciais para a entrega local. O trailer geralmente contém bits para detecção de erros.⁵ Essa estrutura de quadro permite que o fluxo de bits da camada física seja organizado em unidades de dados discretas e gerenciáveis, que podem ser processadas pelo nó receptor.⁹

#### Controle de Acesso ao Meio (Medium Access Control - MAC)

Em canais de difusão (broadcast), onde múltiplos nós compartilham o mesmo meio de transmissão físico — como em redes Ethernet legadas que utilizavam hubs ou em redes sem fio (Wi-Fi) — surge a necessidade de coordenar quem pode transmitir e quando. Se dois ou mais nós transmitirem simultaneamente, seus sinais colidem, resultando em uma transmissão corrompida. O serviço de controle de acesso ao meio, implementado na subcamada MAC da camada de enlace, utiliza protocolos específicos para arbitrar o acesso ao canal, minimizando ou gerenciando colisões.¹¹

#### Entrega Confiável (Reliable Delivery)

A camada de enlace pode, opcionalmente, fornecer um serviço de entrega confiável, garantindo que os quadros sejam transmitidos através do enlace sem erros. Este serviço é tipicamente implementado usando mecanismos de confirmação (acknowledgments - ACKs) e retransmissão. O nó receptor envia um ACK para cada quadro recebido corretamente. Se o nó transmissor não receber um ACK dentro de um determinado período de tempo, ele assume que o quadro foi perdido ou corrompido e o retransmite.²

Este serviço é particularmente valioso em enlaces propensos a altas taxas de erro, como os enlaces sem fio. A correção de um erro em um único salto (hop-by-hop) na camada de enlace é muito mais eficiente do que esperar que o protocolo de transporte de ponta a ponta (como o TCP) detecte a perda e inicie uma retransmissão através de toda a rede. Por outro lado, para meios de transmissão muito confiáveis, como fibra óptica, a taxa de erro de bit é extremamente baixa. Nesses casos, o custo computacional e a sobrecarga de protocolo para implementar a entrega confiável na camada de enlace podem superar os benefícios. Por essa razão, muitos protocolos de LAN com fio, como o Ethernet, optam por um serviço não confiável, delegando a recuperação de erros às camadas superiores.⁵ Esta variação na implementação revela um princípio fundamental do projeto de redes: a confiabilidade é aplicada estrategicamente nas camadas onde é mais eficiente, com base nas características do meio físico subjacente. O objetivo não é a confiabilidade absoluta em cada camada, mas sim uma confiabilidade suficiente para garantir um desempenho robusto de ponta a ponta.

#### Detecção e Correção de Erros (Error Detection and Correction)

A transmissão de sinais pela camada física está sujeita a ruído e atenuação, que podem introduzir erros nos bits (um '1' pode se tornar um '0' e vice-versa).¹⁵ A camada de enlace implementa mecanismos para detectar esses erros. Isso é feito adicionando bits de redundância ao quadro, calculados pelo transmissor com base nos dados do quadro. O receptor realiza o mesmo cálculo e compara seu resultado com os bits de redundância recebidos. Uma discrepância indica que ocorreu um erro.⁷ Em alguns casos, os códigos podem ser robustos o suficiente não apenas para detectar, mas também para corrigir os erros, eliminando a necessidade de retransmissão.¹⁸

#### Controle de Fluxo (Flow Control)

Este serviço é responsável por gerenciar a taxa de transmissão de dados entre nós adjacentes para evitar que um transmissor rápido sobrecarregue um receptor lento. Se o receptor não conseguir processar os quadros na mesma velocidade em que chegam, seus buffers podem transbordar, resultando em perda de dados. O controle de fluxo na camada de enlace garante que o transmissor envie dados apenas na velocidade que o receptor pode suportar.²

### 5.1.2 Implementação

A camada de enlace é implementada predominantemente no adaptador de rede, mais conhecido como Placa de Interface de Rede (Network Interface Card - NIC).³ Uma NIC é um dispositivo de hardware que se conecta ao barramento de um sistema hospedeiro (como um computador ou roteador) e fornece a interface física para a rede.¹⁹

A implementação é uma sinergia entre hardware, software e firmware. No coração da NIC está um controlador da camada de enlace, geralmente um único chip especializado (ASIC) que executa a maioria das funções da camada de enlace — como enquadramento, endereçamento MAC, acesso ao meio e detecção de erros — em hardware. A implementação em hardware é crucial para alcançar as altas velocidades exigidas pelas redes modernas.¹⁹ O componente de software, conhecido como driver de dispositivo, reside no sistema operacional do hospedeiro e atua como a interface entre a pilha de protocolos do SO e o hardware da NIC. Ele gerencia a comunicação entre o SO e o controlador da NIC, orquestrando a transferência de datagramas para a placa para transmissão e a entrega de quadros recebidos para as camadas superiores da pilha.¹⁰ Essa divisão de trabalho permite que a CPU principal do hospedeiro delegue as tarefas intensivas e de baixo nível da camada de enlace para o hardware especializado da NIC, otimizando o desempenho geral do sistema.

## 5.2 Detecção e correção de erros

A transmissão de dados através de meios físicos, sejam eles guiados ou não, está inerentemente sujeita a erros. Ruído eletromagnético, atenuação do sinal e outras formas de interferência podem corromper os bits que compõem um quadro, alterando seu conteúdo original.¹⁵ Para garantir a integridade dos dados, a camada de enlace emprega técnicas de detecção e, por vezes, correção de erros. A abordagem fundamental por trás dessas técnicas é a redundância: bits adicionais, calculados a partir dos dados, são anexados à mensagem. O receptor usa esses bits de redundância para verificar se a mensagem foi recebida corretamente.¹⁴

A detecção de erros é a capacidade de identificar que um erro ocorreu, enquanto a correção de erros vai um passo além, permitindo que o receptor reconstrua a mensagem original sem a necessidade de uma retransmissão. A capacidade de um código de detectar ou corrigir erros está diretamente relacionada à quantidade de redundância adicionada.²⁶

### 5.2.1 Verificações de paridade

#### Paridade Simples

A verificação de paridade simples é a técnica de detecção de erros mais fundamental. Consiste em adicionar um único bit de redundância, o bit de paridade, a um bloco de dados (como um byte). A lógica pode ser de dois tipos²⁷:

- **Paridade Par (Even Parity)**: O bit de paridade é definido como 1 se o número de bits '1' nos dados for ímpar; caso contrário, é 0. O objetivo é fazer com que o número total de bits '1' (dados + paridade) seja sempre par.

- **Paridade Ímpar (Odd Parity)**: O bit de paridade é definido como 1 se o número de bits '1' nos dados for par, garantindo que o número total de bits '1' seja sempre ímpar.

O receptor recalcula a paridade dos dados recebidos e a compara com o bit de paridade recebido. Se houver uma discrepância, um erro foi detectado. A principal limitação da paridade simples é sua incapacidade de detectar um número par de erros de bit no mesmo bloco, pois a contagem de paridade permaneceria correta.²⁷

#### Paridade Bidimensional

Para aumentar a robustez da detecção de erros, a paridade bidimensional (ou paridade dupla) organiza os dados em uma matriz bidimensional (linhas e colunas). Um bit de paridade é calculado para cada linha e para cada coluna.³⁰

**Funcionamento**: Os dados são divididos em blocos, que formam as linhas da matriz. Um bit de paridade (par ou ímpar) é calculado para cada linha. Em seguida, um bit de paridade é calculado para cada coluna, formando uma linha adicional de bits de paridade.

**Capacidades**: Este método é significativamente mais poderoso. Ele pode detectar todos os erros de 1, 2 e 3 bits. Mais importante, ele pode corrigir qualquer erro de bit único. Se um único bit for corrompido, tanto a paridade da sua linha quanto a da sua coluna estarão incorretas. O receptor pode identificar o bit exato do erro na interseção da linha e da coluna com falha e simplesmente invertê-lo para corrigir os dados.³¹ No entanto, certos padrões de erros de 4 bits podem passar despercebidos se ocorrerem nos cantos de um retângulo dentro da matriz, pois as paridades de linha e coluna ainda seriam válidas.³⁴

### 5.2.2 Soma de verificação

A soma de verificação (checksum) é outra técnica de detecção de erros, comumente implementada em software e utilizada em protocolos de camadas superiores, como TCP, UDP e IP.³⁵

**Algoritmo do Checksum da Internet**: O método funciona da seguinte forma:

1. Os dados a serem protegidos são tratados como uma sequência de inteiros de 16 bits.
2. Esses inteiros são somados usando a aritmética de complemento de 1. Nessa aritmética, qualquer "estouro" (carry-out) do bit mais significativo é adicionado de volta ao resultado (wrap around).
3. O complemento de 1 do resultado final dessa soma é o checksum.

**Verificação**: O receptor realiza o mesmo processo: soma todos os inteiros de 16 bits recebidos, incluindo o campo de checksum. Se não houver erros, o resultado da soma final (após o wrap around) será uma sequência de todos os bits '1' (representando o valor -0 na aritmética de complemento de 1).³⁷ Se o resultado for diferente, um erro foi detectado.

**Aplicação**: O checksum é computacionalmente simples, mas oferece uma proteção mais fraca em comparação com o CRC. Sua principal função é proteger contra erros que podem ocorrer durante o processamento dentro de um roteador ou host, onde os dados podem ser corrompidos na memória após a verificação do CRC do quadro de enlace ter sido concluída.³⁹

### 5.2.3 CRC

A Verificação por Redundância Cíclica (CRC) é uma das técnicas de detecção de erros mais poderosas e amplamente utilizadas em redes de computadores, especialmente em protocolos de camada de enlace como Ethernet e Wi-Fi.⁴¹ Sua base matemática está na divisão de polinômios sobre um corpo finito de dois elementos (aritmética binária).⁴⁴

**Fundamento Polinomial**: Uma sequência de bits é tratada como os coeficientes de um polinômio. Por exemplo, a sequência de bits 1101 corresponde ao polinômio 1⋅x³+1⋅x²+0⋅x¹+1⋅x⁰=x³+x²+1.

**Processo de Geração e Verificação**:

1. **Acordo Prévio**: O transmissor e o receptor concordam com um polinômio gerador, G(x), de grau r. Isso corresponde a uma sequência de bits de r+1 bits.

2. **Preparação dos Dados**: O transmissor pega o bloco de dados de d bits, D(x), e o estende adicionando r bits zero ao final. Isso é equivalente a multiplicar o polinômio dos dados por xʳ.

3. **Cálculo do CRC**: O transmissor divide o polinômio estendido, xʳD(x), pelo polinômio gerador G(x) usando a divisão polinomial binária (onde as subtrações são realizadas com a operação XOR).⁴⁶ O resto dessa divisão, R(x), terá r bits e é o valor do CRC.

4. **Transmissão**: O transmissor subtrai (ou, equivalentemente, adiciona via XOR) o resto R(x) do polinômio estendido xʳD(x). O resultado, T(x)=xʳD(x)−R(x), é o quadro que será transmitido. Uma propriedade fundamental dessa operação é que T(x) é perfeitamente divisível por G(x).

5. **Verificação no Receptor**: O receptor recebe o quadro T(x) (que pode ou não conter erros) e o divide pelo mesmo polinômio gerador G(x). Se o resto da divisão for zero, o receptor assume que não houve erros. Se o resto for diferente de zero, um erro foi detectado e o quadro é descartado.⁴⁴

A força do CRC reside na escolha cuidadosa do polinômio gerador, que pode ser otimizado para detectar vários tipos de erros comuns em canais de comunicação, como erros de bit único, erros de bit duplo, qualquer número ímpar de erros e, mais importante, erros em rajada (burst errors) de até r bits de comprimento.⁴²

A presença de mecanismos de verificação de erros em múltiplas camadas da pilha de protocolos, como CRC na camada de enlace e checksum nas camadas de rede e transporte, não é uma redundância desnecessária, mas sim uma estratégia de defesa em profundidade. A verificação da camada de enlace protege a integridade dos dados durante a travessia de um único link físico. No entanto, um pacote é desencapsulado e reencapsulado em cada roteador ao longo de seu caminho. Erros podem ser introduzidos dentro do próprio roteador, por exemplo, por corrupção de memória, após a verificação do quadro de entrada e antes da criação do quadro de saída. Os checksums de ponta a ponta nas camadas de transporte e rede são projetados para detectar precisamente esses tipos de erros que ocorrem dentro dos nós da rede, complementando a proteção fornecida em cada salto pela camada de enlace.⁴⁰

| Técnica | Overhead | Complexidade | Capacidade de Detecção | Camada Típica |
|---------|----------|--------------|------------------------|---------------|
| Paridade Simples | Baixo (1 bit por bloco) | Muito Baixa | Erros de bit único, falha com erros de número par | Enlace |
| Paridade Bidimensional | Moderado (bits de linha + coluna) | Baixa | Erros de 1, 2, 3 bits; corrige erros de bit único | Enlace |
| Checksum da Internet | Baixo (16 bits) | Baixa (Software) | Detecta a maioria dos erros, mas mais fraco que o CRC | Transporte, Rede |
| CRC | Moderado (16-32 bits) | Moderada (Hardware) | Muito robusto, detecta a maioria dos erros em rajada | Enlace |

## 5.3 Protocolos de acesso múltiplo

Quando múltiplos nós (computadores, dispositivos) compartilham um único meio de transmissão, como um cabo coaxial, um canal de rádio sem fio ou um enlace de satélite, surge um problema fundamental: como coordenar o acesso a esse canal compartilhado? Se dois ou mais nós transmitirem simultaneamente, seus sinais irão interferir um com o outro, resultando em uma "colisão", na qual nenhuma das transmissões é recebida corretamente. Os protocolos de acesso múltiplo (ou protocolos MAC - Medium Access Control) são um conjunto de regras que os nós seguem para compartilhar o canal de forma ordenada e eficiente.⁵⁰

Esses protocolos podem ser classificados em três categorias principais: divisão de canal, acesso aleatório e revezamento.⁵⁰

| Categoria | Mecanismo Principal | Protocolos de Exemplo | Prós | Contras |
|-----------|---------------------|----------------------|------|---------|
| Divisão de Canal | Alocação estática de uma "fatia" do canal para cada nó. | FDMA, TDMA, CDMA | Sem colisões, justo sob carga pesada. | Ineficiente sob carga leve (recursos não utilizados). |
| Acesso Aleatório | Nós transmitem à vontade; o protocolo define como detectar e se recuperar de colisões. | ALOHA, CSMA/CD, CSMA/CA | Eficiente sob carga leve, descentralizado. | Propenso a colisões sob carga pesada, reduzindo a vazão. |
| Revezamento | Nós se revezam para transmitir de forma coordenada. | Polling, Token Passing | Eficiente em cargas variadas, sem colisões. | Overhead de coordenação, latência, pontos de falha. |

### 5.3.1 Divisão de canal

Os protocolos de divisão de canal resolvem o problema do acesso múltiplo eliminando completamente a competição. Eles dividem o recurso do canal em "fatias" menores e alocam uma fatia para cada nó de forma exclusiva e permanente.⁵²

**FDMA (Frequency Division Multiple Access - Acesso Múltiplo por Divisão de Frequência)**: O espectro de frequência do canal é dividido em bandas de frequência menores, e cada nó recebe uma banda exclusiva para transmitir. É análogo a diferentes estações de rádio transmitindo em suas próprias frequências designadas. Se um nó não tem nada a transmitir, sua banda de frequência permanece ociosa.⁵²

**TDMA (Time Division Multiple Access - Acesso Múltiplo por Divisão de Tempo)**: O tempo é dividido em quadros (frames) e cada quadro é dividido em um número fixo de slots de tempo. Cada nó é alocado a um slot de tempo específico em cada quadro e só pode transmitir durante seu slot designado. Se um nó não tem dados para enviar durante seu slot, o slot fica vazio e o canal fica ocioso.⁵²

**CDMA (Code Division Multiple Access - Acesso Múltiplo por Divisão de Código)**: Uma abordagem mais sofisticada, o CDMA permite que todos os nós transmitam simultaneamente em toda a faixa de frequência. A separação é alcançada atribuindo a cada nó um código de espalhamento único (chip sequence). O transmissor codifica cada bit de dados com essa sequência de código, espalhando o sinal por uma ampla largura de banda. O receptor, conhecendo o código do transmissor, pode extrair o sinal desejado do ruído de fundo criado por outras transmissões simultâneas.⁵²

A principal vantagem dos protocolos de divisão de canal é a ausência de colisões. No entanto, sua principal desvantagem é a ineficiência quando a carga da rede é baixa ou o tráfego é intermitente, pois a capacidade alocada para nós inativos é desperdiçada.⁵²

### 5.3.2 Acesso aleatório

Em contraste com a alocação estática da divisão de canal, os protocolos de acesso aleatório permitem que os nós transmitam com base em suas necessidades imediatas, sem uma coordenação centralizada. Essa abordagem é altamente eficiente em cargas leves, mas introduz a possibilidade de colisões, que devem ser gerenciadas pelo protocolo.⁵²

**ALOHA**: Desenvolvido para redes de rádio, o ALOHA puro é o protocolo de acesso aleatório mais simples. Um nó transmite assim que tem um quadro para enviar. Se ocorrer uma colisão, o transmissor espera um tempo aleatório antes de tentar novamente.⁵⁹ O Slotted ALOHA melhora a eficiência dividindo o tempo em slots e exigindo que as transmissões comecem apenas no início de um slot. Isso reduz a "janela de vulnerabilidade" para colisões pela metade, dobrando a vazão máxima do canal.⁶⁰

**CSMA/CD (Carrier Sense Multiple Access with Collision Detection)**: Fundamental para as redes Ethernet com fio, o CSMA/CD aprimora o ALOHA com duas regras principais:

- **Carrier Sense**: "Ouvir antes de falar". Um nó verifica se o canal está ocioso antes de transmitir. Se estiver ocupado, ele espera.⁶³

- **Collision Detection**: "Ouvir enquanto fala". Um nó continua a monitorar o canal durante a transmissão. Se detectar que outro nó também começou a transmitir (detectando um nível de sinal anômalo), ele reconhece uma colisão, interrompe imediatamente sua transmissão, envia um sinal de "jam" para garantir que todos os outros nós saibam da colisão e, em seguida, entra em um período de recuo exponencial binário (binary exponential backoff).⁶³ Neste algoritmo, o nó escolhe um tempo de espera aleatório de um intervalo que dobra a cada colisão sucessiva para o mesmo quadro, reduzindo a probabilidade de colisões repetidas.⁶⁶

**CSMA/CA (Carrier Sense Multiple Access with Collision Avoidance)**: Utilizado em redes sem fio como o Wi-Fi (IEEE 802.11), onde a detecção de colisão é impraticável. Como um nó não pode "ouvir" enquanto transmite em um meio sem fio (seu próprio sinal é muito mais forte), o foco muda de detectar colisões para evitá-las.⁶⁴

- **Mecanismo Básico**: O nó ouve o canal. Se estiver ocioso, ele espera por um curto período adicional (um interframe space) e, em seguida, por um tempo de recuo aleatório antes de transmitir. Isso diminui a chance de dois nós que encontram o canal livre ao mesmo tempo transmitirem simultaneamente.⁶⁹

- **Confirmações (ACKs)**: Como as colisões não podem ser detectadas diretamente, o CSMA/CA depende de confirmações (ACKs) do receptor. Se um transmissor não receber um ACK após enviar um quadro, ele assume que ocorreu uma colisão e retransmite o quadro após um procedimento de recuo exponencial.⁶⁹

- **RTS/CTS (Request to Send/Clear to Send)**: Para mitigar o problema do terminal oculto — onde dois nós, A e C, estão fora do alcance um do outro, mas ambos podem se comunicar com um ponto de acesso (AP) B, podendo colidir em B sem saber — o mecanismo RTS/CTS pode ser usado. O nó A envia um pequeno quadro RTS para o AP. O AP responde com um quadro CTS. Todos os nós na área de cobertura do AP, incluindo C, ouvem o CTS e se abstêm de transmitir pelo tempo especificado, permitindo que A transmita para B sem colisões.⁶⁹

### 5.3.3 Revezamento

Os protocolos de revezamento (taking-turns) oferecem um meio-termo entre a alocação rígida da divisão de canal e a natureza caótica do acesso aleatório. Eles introduzem uma coordenação explícita para garantir que apenas um nó transmita por vez, eliminando colisões sob qualquer carga de rede.⁵²

**Sondagem (Polling)**: Um dispositivo mestre (como um ponto de acesso ou controlador central) convida sequencialmente os dispositivos escravos a transmitir. Um escravo só pode enviar dados quando é "sondado" pelo mestre. Este método é altamente controlado e permite a implementação de prioridades (sondando nós de alta prioridade com mais frequência). No entanto, introduz uma latência de sondagem (o tempo que um nó deve esperar por sua vez) e uma sobrecarga de mensagens de sondagem. Além disso, a falha do dispositivo mestre paralisa toda a comunicação.⁷⁶

**Passagem de Bastão (Token Passing)**: Um pequeno quadro especial, chamado "bastão" (token), circula entre os nós em uma ordem predeterminada (geralmente uma anel lógico). Um nó só pode transmitir dados se possuir o bastão. Após a transmissão, ele passa o bastão para o próximo nó na sequência. Este método é descentralizado e justo, mas pode ser ineficiente se poucos nós tiverem dados para enviar, pois o bastão continua a circular, consumindo largura de banda. A perda do bastão ou a falha de um nó pode interromper a operação e requer mecanismos de recuperação complexos.⁷⁶ O exemplo clássico é o protocolo Token Ring (IEEE 802.5).⁸¹

### 5.3.4 DOCSIS

O padrão DOCSIS (Data Over Cable Service Interface Specification) é a tecnologia predominante para fornecer acesso à Internet de alta velocidade sobre as redes de TV a cabo existentes (HFC - Hybrid Fiber-Coaxial).⁸³ Ele representa um caso de estudo prático e sofisticado de um protocolo de acesso múltiplo que combina elementos de diferentes categorias para otimizar o desempenho em seu ambiente específico.

A comunicação em uma rede de cabo é assimétrica e ocorre em dois canais distintos:

**Canal Downstream (do provedor para o usuário)**: Este canal opera em modo de difusão simples. O equipamento central do provedor, chamado CMTS (Cable Modem Termination System), transmite todos os pacotes downstream em uma frequência específica. Cada modem a cabo (Cable Modem - CM) na vizinhança ouve este canal e captura apenas os pacotes endereçados a ele.⁸⁵ Não há necessidade de um protocolo de acesso múltiplo aqui, pois há apenas um transmissor.

**Canal Upstream (do usuário para o provedor)**: Este é um canal de acesso múltiplo, pois muitos CMs precisam compartilhar a mesma largura de banda para enviar dados de volta ao CMTS. O DOCSIS utiliza uma abordagem híbrida inteligente para gerenciar este canal:

- **Divisão de Canal**: O canal upstream é dividido em intervalos de tempo chamados minislots, uma forma de TDMA.⁸³

- **Acesso Aleatório para Requisições**: Para obter permissão para transmitir, um CM deve primeiro solicitar uma alocação de minislots ao CMTS. Essas pequenas mensagens de requisição são enviadas em minislots designados para contenção, usando um mecanismo de acesso aleatório semelhante ao Slotted ALOHA. Colisões podem ocorrer aqui, e os CMs usam um algoritmo de recuo para retransmitir as requisições.⁸³

- **Acesso por Revezamento (Controlado)**: O CMTS atua como um mestre que controla o canal. Ele recebe as requisições dos CMs e aloca minislots específicos para cada CM transmitir seus dados. Ao conceder uma "subvenção" de minislots, o CMTS está efetivamente "sondando" o CM e dando-lhe permissão para transmitir de forma livre de colisões durante aquele período.⁸⁵

Essa combinação permite que o DOCSIS lide eficientemente com o tráfego intermitente e de rajada típico do uso da Internet, usando o acesso aleatório para solicitações rápidas e de baixa sobrecarga, e a alocação TDMA controlada para a transferência de dados em massa sem colisões.

## 5.4 Redes locais comutadas

As Redes Locais (Local Area Networks - LANs) modernas são predominantemente construídas em torno de uma tecnologia central: a comutação de enlace de dados. A transição de meios compartilhados (usando hubs) para meios comutados (usando switches) representou um salto quântico no desempenho e na escalabilidade das LANs. Esta seção explora os blocos de construção fundamentais das LANs comutadas.

### 5.4.1 Endereçamento e ARP

Para que os quadros sejam entregues de um nó a outro dentro de uma LAN, é necessário um sistema de endereçamento na camada de enlace. Este sistema funciona em conjunto com o endereçamento da camada de rede (IP) através de um protocolo de resolução crucial.

#### Endereço MAC (Media Access Control)

Cada adaptador de rede (NIC) no mundo possui um endereço MAC único de 48 bits, que é gravado em seu hardware pelo fabricante. Este endereço, também conhecido como endereço físico ou endereço de hardware, é usado para identificar dispositivos na camada de enlace.⁸⁶ Um endereço MAC é tipicamente representado em formato hexadecimal, como 00:1A:2B:3C:4D:5E. A estrutura é padronizada:

- **Primeiros 24 bits**: O Identificador Único Organizacional (OUI - Organizationally Unique Identifier), atribuído a um fabricante específico pela IEEE.
- **Últimos 24 bits**: Um número de série único atribuído pelo fabricante àquele dispositivo específico.⁸⁷

#### Protocolo de Resolução de Endereços (ARP - Address Resolution Protocol)

Enquanto os endereços MAC são usados para a entrega de quadros em uma LAN (Camada 2), as aplicações e a Internet em geral operam com endereços IP (Camada 3). O ARP é o protocolo que traduz entre esses dois mundos, mapeando um endereço IP conhecido para seu endereço MAC correspondente na mesma sub-rede.⁸⁸

O processo de ARP funciona da seguinte maneira:

1. **Necessidade de Resolução**: Um host de origem (Host A) deseja enviar um datagrama IP para um host de destino (Host B) na mesma LAN. O Host A conhece o endereço IP de B, mas precisa do endereço MAC de B para construir o quadro Ethernet.

2. **Verificação do Cache ARP**: O Host A primeiro consulta sua tabela ARP (ou cache ARP), que armazena mapeamentos IP-MAC recentes para economizar tempo e largura de banda.⁹¹

3. **Requisição ARP (Broadcast)**: Se o mapeamento para o IP de B não for encontrado no cache, o Host A cria uma Requisição ARP. Esta é uma mensagem que pergunta: "Quem tem o endereço IP 192.168.1.10? Por favor, me diga seu endereço MAC." Esta requisição é encapsulada em um quadro Ethernet com o endereço MAC de destino definido como o endereço de broadcast (FF:FF:FF:FF:FF:FF).⁹⁰

4. **Inundação pelo Switch**: O switch da LAN recebe o quadro de broadcast e, por sua natureza, o inunda (floods), enviando-o para todas as portas, exceto a porta de origem. Isso garante que a requisição chegue a todos os dispositivos na LAN.

5. **Resposta ARP (Unicast)**: Todos os nós na LAN recebem e processam a Requisição ARP. No entanto, apenas o Host B, cujo endereço IP corresponde ao solicitado, responderá. O Host B envia uma Resposta ARP diretamente (unicast) para o endereço MAC do Host A (que estava incluído na requisição original), dizendo: "Eu tenho o IP 192.168.1.10, e meu MAC é 00:1A:2B:3C:4D:5E".⁹⁰

6. **Atualização do Cache e Comunicação**: O Host A recebe a resposta, armazena o mapeamento IP-MAC em seu cache ARP e agora pode encapsular o datagrama IP original em um quadro Ethernet com o endereço MAC de destino correto e enviá-lo diretamente para o Host B.⁸⁸

### 5.4.2 Ethernet

Ethernet é a tecnologia de LAN com fio dominante, padronizada pelo IEEE sob a especificação 802.3.⁶¹ Ela define os protocolos da camada física e da subcamada de controle de acesso ao meio (MAC).

#### Estrutura do Quadro Ethernet

Um quadro Ethernet é a unidade de dados que encapsula um pacote da camada de rede para transmissão através do meio físico. Sua estrutura é fundamental para o funcionamento da LAN.⁹⁶ Os campos principais são:

- **Preâmbulo (7 bytes) e Delimitador de Início de Quadro (SFD) (1 byte)**: Juntos, esses 8 bytes formam uma sequência de bits que permite ao NIC receptor sincronizar seu relógio com o do transmissor e identificar o início do quadro.⁹⁶

- **Endereço MAC de Destino (6 bytes)**: O endereço MAC do NIC para o qual o quadro é destinado.

- **Endereço MAC de Origem (6 bytes)**: O endereço MAC do NIC que está enviando o quadro.

- **Tipo/Comprimento (2 bytes)**: Este campo tem um duplo propósito. Se o valor for menor ou igual a 1500, ele indica o comprimento do campo de dados (padrão IEEE 802.3). Se for maior que 1536, ele indica o protocolo da camada superior encapsulado no quadro (por exemplo, 0x0800 para IPv4, 0x0806 para ARP), seguindo o padrão Ethernet II.⁹⁶

- **Dados (Payload) (46-1500 bytes)**: Contém o datagrama da camada de rede. Se o datagrama for menor que 46 bytes, um campo de preenchimento (padding) é adicionado para garantir que o quadro atinja o tamanho mínimo necessário para a detecção de colisão adequada em redes CSMA/CD legadas.⁹⁶ O tamanho máximo de 1500 bytes define a Unidade Máxima de Transmissão (MTU) do Ethernet.

- **Sequência de Verificação de Quadro (FCS) (4 bytes)**: Contém um valor de Verificação de Redundância Cíclica (CRC) de 32 bits. O transmissor calcula o CRC com base nos campos de endereço, tipo e dados. O receptor recalcula o CRC e, se os valores não corresponderem, o quadro é considerado corrompido e descartado.⁹⁶

### 5.4.3 Comutadores

Os comutadores de camada de enlace (switches) são o coração das LANs modernas. Eles operam na Camada 2, tomando decisões de encaminhamento com base nos endereços MAC.⁹⁹ Suas três funções principais são aprender, encaminhar/filtrar e evitar loops.¹⁰²

#### Autoaprendizagem, Encaminhamento e Filtragem

O funcionamento de um switch é um processo dinâmico e eficiente que não requer configuração manual para sua operação básica.¹⁰⁰

**Aprender (Learn)**: O switch constrói e mantém uma tabela de endereços MAC (também chamada de tabela CAM). Ele faz isso examinando o endereço MAC de origem de cada quadro que chega em suas portas. Para cada quadro, o switch armazena o endereço MAC de origem e a porta pela qual o quadro chegou, juntamente com um timestamp. Se uma entrada para aquele MAC já existir, o timestamp é atualizado. Entradas que não são atualizadas por um certo período (geralmente 5 minutos) são removidas (aging).¹⁰⁰

**Encaminhar/Filtrar (Forward/Filter)**: Quando um quadro chega, o switch examina o endereço MAC de destino.

- **Encaminhamento (Forwarding)**: Se o endereço de destino é encontrado na tabela MAC e está associado a uma porta diferente da porta de chegada, o switch encaminha o quadro apenas para essa porta de destino específica. Isso isola o tráfego, garantindo que ele não seja enviado desnecessariamente para outras partes da rede.¹⁰⁵

- **Filtragem (Filtering)**: Se o endereço de destino é encontrado na tabela MAC e está associado à mesma porta pela qual o quadro chegou, o switch simplesmente descarta (filtra) o quadro. Isso acontece em cenários com hubs conectados a uma porta de switch, onde dispositivos no mesmo segmento já receberam o quadro.¹⁰⁸

- **Inundação (Flooding)**: Se o endereço MAC de destino não for encontrado na tabela (um "unicast desconhecido") ou se for um endereço de broadcast (FF:FF:FF:FF:FF:FF), o switch inunda o quadro, ou seja, o envia para todas as portas, exceto a porta de origem.¹⁰⁴ Este mecanismo é o que permite que broadcasts como as requisições ARP funcionem e também como o switch eventualmente aprende a localização do destino quando este responder.

A interação entre o processo de aprendizado do switch e o protocolo ARP é um exemplo elegante de sinergia em redes. Uma requisição ARP, sendo um broadcast, é inundada pelo switch, garantindo que ela alcance o destino pretendido. Ao mesmo tempo, essa requisição permite que o switch aprenda o endereço MAC e a porta do remetente. Quando o destino responde com um unicast, o switch, já tendo aprendido a localização do remetente, pode encaminhar a resposta ARP diretamente para a porta correta, sem precisar inundá-la. Esse processo de bootstrap permite que a rede se autoconfigure de forma eficiente.

### 5.4.4 VLANs

As Redes Locais Virtuais (VLANs) são uma tecnologia que permite a um administrador de rede segmentar uma única infraestrutura de switch físico em múltiplas redes lógicas e isoladas.¹⁰⁹

**Domínios de Broadcast**: A principal função de uma VLAN é criar múltiplos domínios de broadcast em um único switch ou em um conjunto de switches interconectados. Em uma LAN tradicional sem VLANs, uma mensagem de broadcast enviada por qualquer dispositivo é recebida por todos os outros dispositivos na rede. Com VLANs, um broadcast enviado em uma VLAN específica só é recebido pelos dispositivos que pertencem àquela mesma VLAN.¹⁰⁹

**Benefícios**: A segmentação por VLANs oferece vantagens significativas:

- **Segurança**: Isola grupos de usuários e recursos, impedindo que o tráfego de uma VLAN seja visto por outra sem passar por um dispositivo de Camada 3 (roteador).¹⁰⁹
- **Gerenciamento de Tráfego**: Contém o tráfego de broadcast, melhorando o desempenho geral da rede.
- **Flexibilidade**: Permite agrupar usuários e dispositivos logicamente (por departamento, projeto, etc.) independentemente de sua localização física na rede.¹⁰⁹

**Trunking e 802.1Q**: Para que as VLANs se estendam por múltiplos switches, é necessário um link de trunk. Um trunk é uma conexão ponto a ponto entre dois dispositivos de rede (geralmente switches) que transporta o tráfego de múltiplas VLANs.¹⁰⁹ O padrão IEEE 802.1Q define o método de marcação de VLAN (VLAN tagging). Quando um quadro Ethernet atravessa um link de trunk, uma "etiqueta" de 4 bytes é inserida em seu cabeçalho. Esta etiqueta contém um Identificador de VLAN (VID) de 12 bits, que identifica a qual VLAN o quadro pertence. O switch receptor usa este VID para garantir que o quadro seja encaminhado apenas para as portas que pertencem à mesma VLAN.¹⁰⁹

## 5.5 Virtualização de enlace

A virtualização na camada de enlace refere-se a técnicas que abstraem a camada de rede da topologia física subjacente, criando caminhos lógicos ou "virtuais" sobre a infraestrutura física. O MPLS é um exemplo proeminente dessa tecnologia.

### 5.5.1 MPLS

O Multiprotocol Label Switching (MPLS) é uma técnica de encaminhamento de pacotes que opera em uma camada frequentemente descrita como "Camada 2.5", entre a camada de enlace e a camada de rede.¹¹⁷ Em vez de encaminhar pacotes com base nos endereços IP de destino, como fazem os roteadores tradicionais, o MPLS encaminha pacotes com base em rótulos (labels) curtos e de comprimento fixo.

#### Arquitetura e Funcionamento:

**Label Edge Router (LER)**: Quando um pacote IP entra em uma rede MPLS, o primeiro roteador, conhecido como LER de ingresso, realiza uma análise tradicional do cabeçalho IP. Com base em critérios como o endereço IP de destino, classe de serviço, etc., ele classifica o pacote em uma Forwarding Equivalence Class (FEC) — um grupo de pacotes que receberão o mesmo tratamento de encaminhamento. O LER então adiciona um rótulo MPLS ao pacote e o encaminha para o próximo roteador na rede.¹¹⁹

**Label Switching Router (LSR)**: Os roteadores no núcleo da rede MPLS, chamados LSRs, não examinam o cabeçalho IP. Em vez disso, eles usam o rótulo do pacote como um índice para uma tabela de encaminhamento (Label Information Base - LIB). A tabela informa ao LSR qual é o próximo salto e qual novo rótulo deve ser usado. O LSR então troca o rótulo de entrada pelo de saída e encaminha o pacote. Esse processo de "troca de rótulos" é significativamente mais rápido do que uma consulta completa à tabela de roteamento IP.¹¹⁷

**Label-Switched Path (LSP)**: O caminho predeterminado que os pacotes de uma FEC específica seguem através da rede MPLS é chamado de Label-Switched Path (LSP). Essencialmente, um LSP é um circuito virtual estabelecido através da rede de comutação de pacotes.¹¹⁹

**LER de Egresso**: O último roteador no LSP, o LER de egresso, remove o rótulo MPLS e encaminha o pacote IP original para seu destino final usando o roteamento IP padrão.

**Engenharia de Tráfego**: O principal benefício do MPLS é a engenharia de tráfego. Enquanto o roteamento IP tradicional é tipicamente baseado no caminho mais curto e reage dinamicamente às condições da rede, o MPLS permite que os administradores de rede definam explicitamente os caminhos (LSPs) que o tráfego deve seguir. Isso permite um controle granular sobre o uso dos recursos da rede, possibilitando o balanceamento de carga, a prevenção de congestionamentos e a implementação de Qualidade de Serviço (QoS) para diferentes tipos de tráfego, de forma muito mais eficaz do que seria possível apenas com o roteamento IP.¹¹⁷

## 5.6 Redes de datacenter

A arquitetura das redes dentro dos datacenters evoluiu drasticamente para atender às demandas das aplicações modernas, virtualização e computação em nuvem. A mudança mais significativa foi a transição de um padrão de tráfego predominantemente "norte-sul" para um padrão "leste-oeste".¹²²

**Tráfego Norte-Sul vs. Leste-Oeste**:
- **Norte-Sul**: Refere-se ao tráfego que entra ou sai do datacenter (por exemplo, um usuário na internet acessando um servidor web).
- **Leste-Oeste**: Refere-se ao tráfego entre servidores dentro do mesmo datacenter. Aplicações modernas distribuídas, microserviços e migração de máquinas virtuais geram um volume massivo de comunicação leste-oeste.¹²³

A arquitetura hierárquica tradicional de três camadas (núcleo, distribuição e acesso) não é otimizada para o tráfego leste-oeste, pois pode criar gargalos e aumentar a latência. Para resolver isso, a arquitetura leaf-spine (folha-espinha) tornou-se o padrão de fato para redes de datacenter modernas.¹²²

#### Arquitetura Leaf-Spine:

**Topologia de Duas Camadas**: A arquitetura consiste em apenas duas camadas de switches: a camada leaf e a camada spine.

- **Leaf Switches**: Atuam como a camada de acesso. Os servidores e dispositivos de armazenamento se conectam diretamente aos leaf switches, que são tipicamente switches Top-of-Rack (ToR).
- **Spine Switches**: Formam o backbone (núcleo) da rede.

**Interconexão Full-Mesh**: A regra de conectividade é simples e rigorosa: cada leaf switch se conecta a todos os spine switches da rede. Não há conexões diretas entre os spine switches, nem entre os leaf switches.¹²²

#### Vantagens da Arquitetura Leaf-Spine:

**Baixa Latência e Previsibilidade**: Qualquer comunicação entre servidores conectados a diferentes leaf switches sempre atravessa o mesmo número de saltos: do servidor de origem para seu leaf switch, para um spine switch, para o leaf switch de destino e, finalmente, para o servidor de destino. Esse caminho de dois saltos (leaf-spine-leaf) garante uma latência baixa e, crucialmente, previsível.¹²²

**Alta Largura de Banda e Sem Bloqueio**: Como não há loops na topologia, o Spanning Tree Protocol (STP) não é necessário para bloquear links redundantes. Todos os links entre as camadas leaf e spine podem estar ativos simultaneamente. Protocolos de roteamento como o Equal-Cost Multi-Path (ECMP) são usados para distribuir o tráfego por todos os caminhos disponíveis, aumentando drasticamente a largura de banda total e evitando gargalos.¹²²

**Escalabilidade**: A arquitetura é facilmente escalável. Para aumentar a capacidade de encaminhamento (largura de banda leste-oeste), basta adicionar mais spine switches e conectá-los a todos os leafs existentes. Para aumentar a densidade de portas (mais servidores), basta adicionar mais leaf switches e conectá-los a todos os spines existentes. Essa expansão "horizontal" (scale-out) não requer uma reengenharia da rede.¹²²

## 5.7 Um dia na vida de uma requisição Web

Para consolidar os conceitos discutidos, esta seção traça a jornada completa de uma requisição web, desde o momento em que um usuário liga seu computador até a exibição de uma página da web. Este processo ilustra a complexa e elegante interação entre múltiplos protocolos em diferentes camadas da pilha de rede.¹²⁶

### 5.7.1 DHCP, UDP, IP, Ethernet

A jornada começa com a necessidade do computador do usuário obter uma identidade na rede local.

#### Configuração de Rede com DHCP: 

Ao ser ligado e conectado à rede, o computador do usuário não possui um endereço IP. Para obtê-lo, ele utiliza o Dynamic Host Configuration Protocol (DHCP).¹²⁸

**Processo DORA**: O processo DHCP, conhecido como DORA, ocorre em quatro etapas:

1. **Discover (Descoberta)**: O cliente envia uma mensagem DHCPDISCOVER para encontrar servidores DHCP na rede. Como o cliente ainda não tem um endereço IP, esta mensagem é enviada como um broadcast. Ela é encapsulada em um segmento UDP (porta de destino 67), que por sua vez é encapsulado em um datagrama IP (IP de origem 0.0.0.0, IP de destino 255.255.255.255) e, finalmente, em um quadro Ethernet (MAC de destino FF:FF:FF:FF:FF:FF).¹²⁸

2. **Offer (Oferta)**: Um servidor DHCP na rede responde com uma mensagem DHCPOFFER, oferecendo um endereço IP disponível e outras informações de configuração, como a máscara de sub-rede, o endereço IP do roteador de gateway padrão e o endereço IP do servidor DNS.¹²⁸

3. **Request (Requisição)**: O cliente responde com uma mensagem DHCPREQUEST, aceitando formalmente a oferta.

4. **Acknowledge (Confirmação)**: O servidor finaliza o processo com uma mensagem DHCPACK, confirmando a concessão (lease) do endereço IP ao cliente.¹²⁹

Com este processo concluído, o computador do usuário agora possui um endereço IP, sabe como alcançar outras redes (através do gateway padrão) e sabe a quem perguntar sobre nomes de domínio (o servidor DNS).

### 5.7.2 DNS, ARP

Com a configuração de rede estabelecida, o usuário abre um navegador e digita uma URL, como http://www.example.com.

**Resolução de Nome com DNS**: O navegador precisa traduzir o nome de domínio www.example.com para um endereço IP. Para isso, o sistema operacional do cliente cria uma consulta DNS.¹³¹ Esta consulta é tipicamente encapsulada em um segmento UDP (porta de destino 53) e endereçada ao servidor DNS cujo IP foi fornecido pelo DHCP.⁹¹

**Resolução de Endereço Físico com ARP**: Para enviar o pacote DNS ao servidor DNS (que pode estar em uma rede diferente), o cliente primeiro precisa enviar o pacote ao seu roteador de gateway padrão. O cliente conhece o endereço IP do gateway (fornecido pelo DHCP), mas não o seu endereço MAC. O protocolo ARP é usado para resolver isso. O cliente envia uma requisição ARP em broadcast na LAN, perguntando "Quem tem o IP do gateway?". O roteador responde com seu endereço MAC.⁸⁸

**Entrega da Consulta DNS**: Com o endereço MAC do gateway em mãos, o cliente encapsula o datagrama IP contendo a consulta DNS em um quadro Ethernet endereçado ao MAC do gateway e o transmite na rede local. O gateway, ao receber o quadro, desencapsula o datagrama IP e o encaminha pela Internet em direção ao servidor DNS.

**Resposta DNS**: Após o processo de resolução hierárquica (envolvendo servidores raiz, TLD e autoritativos), o servidor DNS responde ao cliente com o endereço IP correspondente a www.example.com.¹³¹

### 5.7.3 Roteamento

Agora que o cliente possui o endereço IP do servidor web de destino, ele pode iniciar a comunicação direta.

**Encaminhamento Hop-by-Hop**: O cliente cria um pacote IP com seu próprio endereço IP como origem e o endereço IP de www.example.com como destino. Este pacote é enviado ao gateway padrão. Cada roteador ao longo do caminho da Internet executa a função de repasse (forwarding): ele examina o endereço IP de destino do pacote, consulta sua tabela de encaminhamento (forwarding table) para determinar o próximo salto e envia o pacote para o próximo roteador na rota.¹³⁴

**Protocolos de Roteamento**: As tabelas de encaminhamento em cada roteador são construídas e mantidas dinamicamente por protocolos de roteamento. Dentro de uma mesma rede de provedor (um Sistema Autônomo - AS), protocolos de gateway interior (IGPs) como OSPF (Open Shortest Path First) calculam as melhores rotas internas.¹³⁷ Para trocar informações de alcançabilidade entre diferentes ASes (ou seja, através da Internet global), o protocolo de gateway exterior BGP (Border Gateway Protocol) é utilizado.¹³⁸

### 5.7.4 TCP e HTTP

Com uma rota estabelecida pela camada de rede, a comunicação confiável é estabelecida pela camada de transporte.

**Estabelecimento da Conexão TCP (Three-Way Handshake)**: Antes de enviar a requisição da página web, o navegador precisa estabelecer uma conexão confiável com o servidor web. Isso é feito através do handshake de três vias do TCP¹⁴⁰:

1. **SYN**: O cliente envia um segmento TCP com o flag SYN (sincronizar) ativado para o servidor.
2. **SYN-ACK**: O servidor responde com um segmento que tem os flags SYN e ACK (confirmação) ativados.
3. **ACK**: O cliente envia um segmento final com o flag ACK ativado, confirmando o recebimento do SYN-ACK do servidor. A conexão está agora estabelecida e pronta para a transferência de dados.

**Requisição HTTP**: O navegador constrói uma mensagem de requisição HTTP, como GET /index.html HTTP/1.1, e a envia através da conexão TCP estabelecida. Esta mensagem é o "dado" ou "payload" para a camada TCP.¹⁴³

**Segmentação TCP**: O TCP pega o fluxo de bytes da mensagem HTTP, divide-o em segmentos, adiciona um cabeçalho TCP a cada um (contendo portas de origem e destino, números de sequência e confirmação, etc.) e os entrega à camada IP para transmissão.¹⁴⁴

**Resposta HTTP**: O servidor web recebe a requisição HTTP, processa-a (por exemplo, lendo o arquivo index.html do disco) e envia de volta uma resposta HTTP. A resposta consiste em uma linha de status (ex: HTTP/1.1 200 OK), cabeçalhos de resposta e o corpo da mensagem contendo o HTML da página.¹⁴³

**Renderização e Conexões Adicionais**: O navegador recebe a resposta HTTP, analisa o HTML e começa a renderizar a página. Durante a análise, ele pode encontrar referências a outros recursos (imagens, arquivos CSS, scripts JavaScript). Para cada um desses recursos, o navegador iniciará novas requisições HTTP, que podem reutilizar a conexão TCP existente se forem conexões persistentes (padrão no HTTP/1.1).¹⁴⁷

**Encerramento da Conexão**: Após a transferência de todos os dados, a conexão TCP é encerrada de forma ordenada usando um processo de quatro vias com segmentos contendo o flag FIN (finalizar).¹⁴⁰

| Protocolo | Camada | Função Principal na Requisição Web |
|-----------|--------|-------------------------------------|
| Ethernet | Enlace | Transfere quadros (contendo pacotes IP) entre nós na mesma LAN. |
| IP | Rede | Fornece endereçamento global e encaminha datagramas entre redes. |
| ARP | Enlace/Rede | Mapeia endereços IP para endereços MAC dentro da LAN. |
| DHCP | Aplicação | Atribui automaticamente um endereço IP e outras configurações de rede ao cliente. |
| UDP | Transporte | Fornece transporte não confiável para mensagens DHCP e DNS. |
| DNS | Aplicação | Traduz nomes de domínio legíveis por humanos em endereços IP. |
| TCP | Transporte | Estabelece uma conexão confiável, controla o fluxo e o congestionamento para a transferência de dados HTTP. |
| HTTP | Aplicação | Define o formato das mensagens de requisição e resposta para a transferência de recursos web. |