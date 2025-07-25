# Curso de Cibersegurança: Fundamentos e Técnicas Avançadas

### Nível 1: Fundamentos Essenciais

#### MÓDULO 1: Introdução à Cibersegurança
Este módulo estabelece os fundamentos da cibersegurança, com uma abordagem prática e interativa, incluindo laboratórios introdutórios e um foco em ética e conformidade.

##### Conteúdo Detalhado (Ordenado):
- **História da cibersegurança e evolução das ameaças**: Estudo da evolução, desde o worm Morris (1988) até ransomware moderno (ex.: LockBit 3.0). Análise de casos como o ataque à SolarWinds (2020).
- **Definições fundamentais: vulnerabilidade, ameaça, risco, exploit**: Explicação com exemplos reais (ex.: CVE-2023-1234 para vulnerabilidades; ransomware como ameaça; impacto financeiro como risco).
- **CIA Triad: Confidencialidade, Integridade, Disponibilidade**: Aplicação prática com cenários (ex.: vazamento de dados de um hospital, ataque DDoS a um e-commerce).
- **Tipos de atacantes: script kiddies, hacktivistas, APTs, criminosos**: Estudo de perfis, como Anonymous (hacktivismo), Lazarus Group (APT), e grupos de ransomware (REvil).
- **Tipos de testes: white box, black box, gray box**: Simulações em ambientes controlados (ex.: TryHackMe - Basic Pentesting) para entender diferenças práticas.
- **Ética hacker: divulgação responsável, bug bounties**: Redação de relatórios éticos para plataformas como HackerOne, com exemplos de CVEs reportadas.
- **Leis brasileiras: Lei Carolina Dieckmann, Marco Civil da Internet, LGPD**: Análise de artigos (ex.: Art. 154-A do Código Penal) e casos reais (ex.: multas LGPD em 2023).
- **Crimes cibernéticos no Código Penal brasileiro**: Estudo de invasão de dispositivo (Art. 154-A) e interrupção de serviço (Art. 266), com exemplos judiciais.
- **Conformidade e frameworks: ISO 27001, NIST, CIS Controls**: Mapeamento prático de controles CIS v8 em um ambiente simulado.
- **Zero Trust: conceitos e aplicações**: Introdução ao modelo Zero Trust para autenticação contínua e validação de acessos.

#### MÓDULO 2: Dominando Linux e Shell para Pentesters
Este módulo cobre Linux e Bash com uma progressão do básico ao avançado, incluindo automação e integração com Python.

##### Conteúdo Detalhado (Ordenado):
- **Comandos básicos: ls, cd, pwd, mkdir, rmdir, cp, mv, rm**: Navegação e manipulação de arquivos em Kali Linux, com exercícios práticos (ex.: criar uma estrutura de diretórios).
- **Manipulação de arquivos: cat, less, more, head, tail**: Visualização de logs (ex.: /var/log/syslog) e extração de trechos específicos.
- **Permissões: chmod, chown, chgrp, umask**: Configuração de permissões (ex.: chmod 755 script.sh) e análise de permissões em arquivos sensíveis.
- **Processos: ps, top, htop, kill, killall, jobs**: Monitoramento de processos (ex.: htop para CPU) e término de processos maliciosos.
- **Redirecionamento: pipes, >, >>, <, tee**: Combinação de comandos (ex.: cat log.txt | grep "error" > erros.txt) para análise de logs.
- **Editores de texto: nano, vi/vim, comandos básicos**: Edição de arquivos de configuração (ex.: /etc/hosts) com vim.
- **Compressão: tar, gzip, zip, unzip**: Criação e extração de arquivos (ex.: tar -czvf backup.tar.gz /home/user).
- **Rede: ping, traceroute, ifconfig, ip**: Testes de conectividade (ex.: ping google.com) e configuração de interfaces (ex.: ip addr).
- **Expressões regulares: grep, sed, awk**: Busca de padrões (ex.: grep "login" auth.log) e substituição de texto (ex.: sed \'s/old/new/g\' file.txt).
- **Bash scripting: variáveis, condicionais, loops**: Criação de scripts para automatizar tarefas (ex.: script para verificar portas abertas).
- **Tarefas agendadas: cron, at**: Configuração de tarefas automáticas (ex.: agendar backup diário com cron).
- **Permissões avançadas: SUID, SGID, sticky bit**: Exploração de binários SUID (ex.: /usr/bin/passwd) em laboratórios.
- **Processos avançados: nohup, screen, tmux**: Execução de processos persistentes (ex.: nohup python script.py &).
- **Rede avançada: netstat, ss, ncat**: Análise de conexões (ex.: ss -tuln) e transferência de dados com ncat.


#### MÓDULO 3: Fundamentos de Redes para Pentesters
Este módulo foi revisado para incluir uma seção detalhada sobre portas e uma progressão clara, com mais laboratórios práticos.

##### Conteúdo Detalhado (Ordenado):
- **Conceitos básicos de redes: terminologia, topologias**: Termos como LAN, WAN, switch, roteador; topologias como estrela e malha, com exemplos reais (ex.: redes corporativas).
- **Modelo OSI: 7 camadas e funções práticas**: Estudo de cada camada (ex.: Física - cabos Ethernet; Aplicação - HTTP) com cenários práticos.
- **Pilha TCP/IP: camadas e protocolos**: Diferenças entre OSI e TCP/IP; protocolos como IP, TCP, UDP e HTTP.
- **Conceito de portas: TCP/UDP, portas conhecidas, efêmeras**: Explicação de portas (ex.: 80/HTTP, 443/HTTPS), portas efêmeras (49152–65535), e sua relevância em varreduras (ex.: Nmap) e firewalls.
- **Endereçamento IP: IPv4, IPv6, classes de IP**: Estrutura de IPv4 (ex.: 192.168.1.1), IPv6 (ex.: 2001:db8::1), e classes A/B/C.
- **Subnetting: máscaras, CIDR, cálculo**: Cálculo de sub-redes (ex.: 192.168.1.0/24 para 256 hosts) e uso de CIDR.
- **Protocolos de camada 2: Ethernet, ARP**: Funcionamento do Ethernet (quadros) e ARP (mapeamento IP-MAC).
- **Protocolos de camada 3: IP, ICMP**: Roteamento com IP e diagnósticos com ICMP (ex.: ping, traceroute).
- **Protocolos de camada 4: TCP, UDP, flags**: Diferenças entre TCP (flags como SYN/ACK) e UDP; análise de handshakes TCP.
- **DNS: resolução, registros (A, MX, CNAME)**: Como o DNS resolve domínios (ex.: google.com para 8.8.8.8) e tipos de registros.
- **DHCP: processo DORA, alocação dinâmica**: Mecanismo de atribuição de IPs (Discover, Offer, Request, Acknowledge).
- **Configuração de switches/roteadores: VLANs, rotas estáticas**: Configuração prática em simuladores como Packet Tracer.
- **Wireshark: instalação, filtros básicos/avançados**: Captura de pacotes e filtros (ex.: tcp.port == 80) para análise de tráfego.
- **VLANs: segmentação, trunking**: Configuração de VLANs para isolar tráfego (ex.: VLAN 10 para servidores).
- **Firewalls: stateful, stateless, regras**: Configuração de regras (ex.: iptables para bloquear porta 22).
- **SSL/TLS: handshake, certificados X.509**: Processo de handshake e análise de certificados com OpenSSL.
- **Vulnerabilidades: DNS spoofing, ARP poisoning**: Exploração de fraquezas (ex.: envenenamento de cache DNS).
- **Técnicas de bypass: fragmentação, túneis**: Métodos para contornar firewalls (ex.: túneis SSH).



### Nível 2: Ferramentas e Técnicas Fundamentais

#### MÓDULO 4: Fundamentos de Python para Cibersegurança
Este módulo ensina Python com foco em automação e desenvolvimento de ferramentas de segurança.

##### Conteúdo Detalhado (Ordenado):
- **Sintaxe Python: variáveis, tipos, entrada/saída**: Uso de strings, listas, dicionários (ex.: dict = {"ip": "192.168.1.1"}).
- **Estruturas de controle: if, for, while, try/except**: Criação de loops e tratamento de erros (ex.: try/except para conexões de rede).
- **Ambiente: Python 3, pip, virtualenv, VS Code**: Configuração de ambientes virtuais (ex.: python -m venv env).
- **Funções: argumentos, lambda, escopo**: Criação de funções (ex.: def scan_port(ip, port):).
- **Módulos: import, criação, pip**: Uso de módulos como requests e instalação via pip.
- **Manipulação de arquivos: txt, CSV, JSON**: Leitura/escrita de arquivos (ex.: json.load() para logs).
- **Expressões regulares: re para logs**: Busca de padrões (ex.: re.search(r"\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}", log)).
- **Bibliotecas: requests, BeautifulSoup, scapy**: Uso para web scraping, parsing e análise de pacotes.
- **Web scraping: BeautifulSoup, Scrapy**: Extração de dados de sites (ex.: scraping de preços).
- **APIs: Shodan, VirusTotal, autenticação**: Conexão com APIs (ex.: Shodan API para busca de hosts).
- **Scapy: sniffing, crafting de pacotes**: Criação de pacotes TCP (ex.: scapy.TCP(dport=80)).
- **Criptografia: cryptography, pycryptodome**: Implementação de AES e RSA em Python.
- **SSH: paramiko para automação**: Conexão remota (ex.: paramiko.SSHClient()).
- **Automação: varredura de portas, enumeração**: Scripts para varredura com socket ou python-nmap.
- **Integração: Metasploit, Nmap**: Uso de pymetasploit3 e python-nmap.
- **Boas práticas: PEP 8, docstrings**: Escrita de código legível e documentado.
- **Projeto: scanner de vulnerabilidades**: Desenvolvimento de um scanner XSS ou SQLi.

#### MÓDULO 5: Dominando Reconhecimento em Pentest
Este módulo foca em reconhecimento, com ênfase em OSINT e enumeração avançada.

##### Conteúdo Detalhado (Ordenado):
- **Metodologia: passivo vs ativo**: Diferenças entre reconhecimento sem interação (passivo) e com interação (ativo).
- **OSINT Framework: fontes públicas**: Uso de fontes como WHOIS, Google e redes sociais.
- **Google Dorking: operadores avançados**: Uso de "inurl:login" e "filetype:pdf site:*.gov" para encontrar dados sensíveis.
- **Whois: domínios, ASNs**: Coleta de informações de registro (ex.: whois domain.com).
- **Redes sociais: LinkedIn, Twitter, Maltego**: Extração de dados de perfis públicos (ex.: Maltego para conexões).
- **Vazamentos: HaveIBeenPwned, Dehashed**: Verificação de credenciais expostas.
- **DNS: dig, nslookup, fierce**: Enumeração de registros DNS (ex.: dig NS example.com).
- **Shodan: dispositivos IoT, portas**: Busca por dispositivos expostos (ex.: câmeras IP).
- **Censys: certificados, hosts**: Análise de certificados SSL para subdomínios.
- **theHarvester: e-mails, subdomínios**: Coleta de dados OSINT (ex.: theHarvester -d example.com).
- **Sublist3r: enumeração de subdomínios**: Descoberta de subdomínios (ex.: sublist3r -d example.com).
- **Amass: mapeamento de domínios**: Enumeração avançada com OWASP Amass.
- **Recon-ng: workspaces, módulos**: Uso de módulos como whois_pocs e bing_domain_web.
- **Maltego: análise de links**: Visualização de conexões entre entidades (ex.: domínios e e-mails).
- **Aquatone: capturas de tela**: Geração de relatórios visuais de sites.
- **Logs de certificados: crt.sh**: Uso de logs de transparência para encontrar subdomínios.

#### MÓDULO 6: Fundamentos de Criptografia e Senhas
Este módulo cobre criptografia, com foco em aplicações práticas e ataques modernos.

##### Conteúdo Detalhado (Ordenado):
- **História da criptografia: cifra de César, Enigma**: Evolução desde cifras clássicas até máquinas criptográficas da Segunda Guerra.
- **Criptografia simétrica: AES, DES, modos de operação**: Estudo do AES-256 (ex.: uso em VPNs) e modos como CBC e GCM.
- **Criptografia assimétrica: RSA, ECC, Diffie-Hellman**: Funcionamento do RSA (2048 bits) e troca de chaves Diffie-Hellman.
- **Funções hash: MD5, SHA-256, colisões**: Propriedades de hashes e vulnerabilidades (ex.: colisões em MD5).
- **PKI: certificados, CAs, cadeia de confiança**: Estrutura de certificados X.509 e autoridades como Let’s Encrypt.
- **Assinaturas digitais: verificação, integridade**: Uso de assinaturas para autenticar mensagens (ex.: GPG).
- **HMAC: autenticação baseada em hash**: Implementação de HMAC-SHA256 para verificar integridade.
- **Geradores de números aleatórios: PRNG, TRNG**: Diferenças entre pseudoaleatórios (ex.: /dev/urandom) e verdadeiros.
- **Políticas de senhas: força, entropia**: Avaliação de entropia (ex.: zxcvbn para medir força).
- **Listas de palavras: SecLists, RockYou**: Uso de listas para ataques de força bruta (ex.: RockYou.txt).
- **Ataques a senhas: dicionário, força bruta, máscaras**: Técnicas com Hashcat (ex.: ataque híbrido).
- **Hashcat: instalação, modos de ataque**: Configuração e uso (ex.: hashcat -m 0 para MD5).
- **John the Ripper: regras personalizadas**: Criação de regras para ataques otimizados.
- **Tabelas rainbow: construção, uso**: Uso de rainbow tables para quebra rápida de hashes.
- **OpenSSL: criptografia prática**: Comandos para criptografar arquivos (ex.: openssl enc -aes-256-cbc).
- **GPG: assinatura, criptografia**: Configuração de GPG para e-mails seguros.
- **Criptografia quântica: fundamentos**: Introdução à criptografia pós-quântica (ex.: algoritmos baseados em lattice).

### Nível 3: Aplicação e Defesa

#### MÓDULO 7: Fundamentos de Privacidade e Anonimato
Este módulo aborda privacidade e anonimato, com foco em ferramentas modernas e OPSEC.

##### Conteúdo Detalhado (Ordenado):
- **Privacidade vs anonimato: diferenças conceituais**: Privacidade (proteger dados) vs anonimato (ocultar identidade).
- **Modelagem de ameaças: STRIDE, DREAD**: Uso de frameworks para identificar riscos (ex.: STRIDE para ameaças).
- **Metadados: remoção, minimização**: Remoção de metadados em PDFs e imagens (ex.: exiftool).
- **VPNs: OpenVPN, WireGuard, kill switch**: Configuração de VPNs com kill switch para evitar vazamentos.
- **Proxies: SOCKS5, HTTP, configuração**: Uso de proxies (ex.: proxychains) para mascarar tráfego.
- **Tor: nós, circuitos, serviços onion**: Funcionamento do Tor e configuração de serviços ocultos.
- **Tor Browser: configurações seguras**: Ajustes de segurança (ex.: nível Safest) e extensões (uBlock Origin).
- **E-mail seguro: ProtonMail, Tutanota, PGP**: Configuração de PGP para e-mails criptografados.
- **Mensagens seguras: Signal, Element, OTR**: Uso de Signal com criptografia ponta a ponta.
- **Criptomoedas: Bitcoin, Monero, mixers**: Transações anônimas com Monero e mixers.
- **TAILS: instalação, uso ao vivo**: Configuração do TAILS para operações seguras.
- **Whonix: isolamento de rede**: Uso do Whonix para evitar vazamentos de IP.
- **I2P: serviços ocultos, configuração**: Configuração de nós I2P para anonimato.
- **OPSEC: compartimentalização, higiene digital**: Práticas como uso de pseudônimos e dispositivos dedicados.
- **Contravigilância: detectar rastreamento**: Identificação de cookies de rastreamento e beacons.
- **Cadeias de proxies: configuração avançada**: Uso de múltiplos proxies para maior anonimato.


#### MÓDULO 8: Fundamentos de Segurança Web e Cloud
Este módulo introdutório explica como funcionam aplicações web e conceitos de segurança em nuvem, cobrindo arquitetura, protocolos e componentes.

##### Conteúdo Detalhado (Ordenado):
- **Arquitetura cliente-servidor: funcionamento básico**: Como clientes (navegadores) se comunicam com servidores via HTTP/HTTPS.
- **Protocolos web: HTTP, HTTPS, WebSockets**: Estrutura de requisições/respostas HTTP (ex.: GET /index.html) e WebSockets para comunicação em tempo real.
- **Componentes de uma aplicação web: front-end, back-end, banco de dados**: Diferenças entre front-end (HTML/CSS/JS), back-end (PHP, Python) e bancos (MySQL, PostgreSQL).
- **HTML, CSS, JavaScript: fundamentos**: Estrutura de páginas (HTML), estilização (CSS) e interatividade (JavaScript).
- **APIs REST: endpoints, métodos**: Estrutura de APIs (ex.: GET /api/users) e métodos (POST, PUT, DELETE).
- **Cookies e sessões: gerenciamento de estado**: Como cookies armazenam dados de sessão (ex.: session_id).
- **Cabeçalhos HTTP: User-Agent, Content-Type**: Análise de cabeçalhos para segurança (ex.: X-Frame-Options).
- **Web servers: Apache, Nginx**: Configuração básica de servidores web.
- **Bancos de dados: SQL, NoSQL**: Diferenças entre MySQL (SQL) e MongoDB (NoSQL).
- **Frameworks web: Django, Flask, React**: Introdução a frameworks populares.
- **Ciclo de vida de requisições: DNS, TCP, HTTP**: Processo completo de uma requisição web.
- **Segurança básica: OWASP Top 10 introdução**: Visão geral de vulnerabilidades como XSS e SQLi.
- **Ferramentas de inspeção: DevTools, Postman**: Uso de DevTools para inspecionar tráfego e Postman para testar APIs.
- **Modelos de nuvem: IaaS, PaaS, SaaS**: Diferenças e responsabilidades (ex.: AWS EC2 vs Lambda).
- **AWS: IAM, S3, EC2**: Configuração segura de permissões e buckets.
- **Azure: Active Directory, VMs**: Gerenciamento de identidades e máquinas virtuais.
- **GCP: IAM, Cloud Storage**: Configuração de políticas de acesso.
- **Configurações incorretas: buckets públicos**: Identificação de S3 públicos (ex.: aws s3 ls).
- **Containers: Docker, Kubernetes**: Segurança de imagens Docker (ex.: Trivy).
- **Serverless: AWS Lambda, Azure Functions**: Configuração segura de funções.
- **VPCs: segmentação de rede**: Configuração de redes privadas virtuais.
- **CloudTrail: monitoramento de logs**: Análise de logs para auditoria.

##### Ferramentas Essenciais:
- **Inspeção Web**: `DevTools` (navegador), `Postman`.
- **Gerenciamento de Nuvem (CLI/SDK)**: `aws cli` (para S3, EC2, IAM), `az cli` (Azure), `gcloud cli` (GCP).
- **Segurança de Containers**: `Trivy`.
- **Auditoria de Nuvem**: `ScoutSuite`, `Prowler`.
- **Segurança Kubernetes**: `Kube-Hunter`.

#### MÓDULO 9: Metodologias de Pentest e Ética Hacker
Este módulo foca em metodologias profissionais de pentest, ética e conformidade.

##### Conteúdo Detalhado (Ordenado):
- **Metodologias: PTES, OSSTMM**: Estudo de frameworks de pentest.
- **Pré-engajamento: escopo, ROE**: Definição de regras de engajamento.
- **OSINT: inteligência inicial**: Coleta de dados com Maltego.
- **Modelagem de ameaças: STRIDE**: Identificação de riscos com STRIDE.
- **Varredura: Nessus, Nuclei**: Uso de scanners de vulnerabilidades.
- **Exploração: Metasploit, manual**: Desenvolvimento de exploits.
- **Pós-exploração: persistência, exfiltração**: Configuração de backdoors.
- **Relatórios: resumo executivo, técnico**: Redação de relatórios profissionais.
- **Web: OWASP Testing Guide**: Testes baseados no OWASP.
- **Mobile: OWASP MSTG**: Testes de apps móveis.
- **Wireless: 802.11, WIDS**: Avaliação de redes WiFi.
- **Engenharia social: phishing simulado**: Campanhas com Gophish.
- **Conformidade: PCI DSS, ISO 27001**: Auditoria de padrões regulatórios.
- **Red team: emulação de adversário**: Simulação de APTs.
- **Purple team: colaboração**: Trabalho com blue teams.
- **Cloud: metodologias AWS/Azure**: Testes em ambientes de nuvem.
- **ICS/SCADA: segurança industrial**: Avaliação de sistemas industriais.
- **Ética hacker: divulgação responsável, bug bounties**: Redação de relatórios éticos para plataformas como HackerOne, com exemplos de CVEs reportadas.
- **Leis brasileiras: Lei Carolina Dieckmann, Marco Civil da Internet, LGPD**: Análise de artigos (ex.: Art. 154-A do Código Penal) e casos reais (ex.: multas LGPD em 2023).
- **Crimes cibernéticos no Código Penal brasileiro**: Estudo de invasão de dispositivo (Art. 154-A) e interrupção de serviço (Art. 266), com exemplos judiciais.




## TRILHA SEGURANÇA DE REDES (VERDE)
*   **Pré-requisitos:** Conclusão da Trilha Principal.

### MÓDULO NETWORK 1: Pentest em Infraestruturas de Redes
Este módulo foca em pentest de redes, com laboratórios práticos e cenários reais.

##### Conteúdo Detalhado (Ordenado):
- **Descoberta de hosts: ping sweep, ARP scan**: Uso de Nmap (ex.: nmap -sn 192.168.1.0/24) para identificar hosts.
- **Varredura de portas: SYN, Connect, UDP**: Técnicas com Nmap (ex.: nmap -sS para SYN scan).
- **Enumeração de serviços: banners, versões**: Coleta de informações (ex.: nmap -sV).
- **Enumeração SMB: smbclient, enum4linux**: Identificação de compartilhamentos (ex.: smbclient -L //host).
- **Enumeração web: dirb, gobuster**: Varredura de diretórios (ex.: gobuster dir -u http://site.com).
- **Enumeração de bancos: MySQL, PostgreSQL**: Tentativas de conexão (ex.: mysql -h host -u root).
- **Enumeração SNMP: snmpwalk, onesixtyone**: Coleta de dados SNMP (ex.: snmpwalk -c public host).
- **Scanners: Nessus, OpenVAS**: Configuração e análise de relatórios de vulnerabilidades.
- **Metasploit: módulos, payloads**: Uso de módulos (ex.: exploit/windows/smb/ms17_010_eternalblue).
- **Exploração manual: injeção SQL**: Exploração manual de vulnerabilidades SQL.
- **Movimentação lateral: pass-the-hash**: Uso de hashes NTLM com Responder.
- **Pivoting: túneis SSH, Chisel**: Criação de túneis (ex.: ssh -L 8080:target:80).
- **Escalação: configurações incorretas**: Exploração de permissões mal configuradas.
- **Persistência: tarefas agendadas**: Configuração de crons ou serviços para acesso contínuo.
- **Nmap avançado: scripts NSE, evasão**: Uso de scripts (ex.: nmap --script vuln).
- **Exploração avançada: buffer overflows**: Desenvolvimento de exploits para overflows.
- **Metasploit avançado: payloads personalizados**: Criação de payloads com msfvenom.

##### Ferramentas Essenciais:
- **Descoberta e Varredura**: `Nmap`, `smbclient`, `enum4linux`, `dirb`, `gobuster`, `snmpwalk`, `onesixtyone`.
- **Scanners de Vulnerabilidades**: `Nessus`, `OpenVAS`.
- **Exploitation Frameworks**: `Metasploit` (msfconsole, msfvenom).
- **Pós-Exploração**: `Responder`, `Chisel`.

### MÓDULO NETWORK 2: Ataques em Redes WiFi
Este módulo cobre ataques WiFi, com foco em ferramentas modernas e cenários práticos.

##### Conteúdo Detalhado (Ordenado):
- **Padrões 802.11: a/b/g/n/ac/ax**: Características e frequências (2.4/5 GHz).
- **Protocolos: WEP, WPA2, WPA3**: Fraquezas do WEP e melhorias do WPA3.
- **Modo monitor: airmon-ng, adaptadores**: Configuração de adaptadores (ex.: Alfa AWUS036NHA).
- **Aircrack-ng: airodump-ng, aireplay-ng**: Captura de pacotes (ex.: airodump-ng wlan0).
- **Ataques de desautenticação: aireplay-ng**: Desconexão de clientes (ex.: aireplay-ng --deauth).
- **Quebra de WEP: ataques de IV**: Exploração de vetores de inicialização.
- **WPA/WPA2: captura de handshake**: Captura com airodump-ng e quebra com Hashcat.
- **Hashcat WPA: regras, máscaras**: Quebra de handshakes (ex.: hashcat -m 2500).
- **WPS: Reaver, Pixie Dust**: Exploração de PINs WPS (ex.: reaver -b BSSID).
- **Evil Twin: hostapd, dnsmasq**: Criação de APs falsos para capturar credenciais.
- **Rogue AP: WiFi-Pumpkin3**: Configuração de portais cativos.
- **EAP: ataques em redes corporativas**: Exploração de autenticação EAP-TLS.
- **Bluetooth: bluez, hcitool**: Escaneamento de dispositivos Bluetooth.
- **Análise de RF: espectro, interferência**: Uso de analisadores como WiFi Analyzer.
- **Segurança física: posicionamento de APs**: Estratégias para proteger APs.

##### Ferramentas Essenciais:
- **Ataques WiFi**: `airmon-ng`, `aircrack-ng`, `airodump-ng`, `aireplay-ng`, `Hashcat`, `Reaver`, `hostapd`, `dnsmasq`, `WiFi-Pumpkin3`.
- **Ataques Bluetooth**: `bluez`, `hcitool`.
- **Análise de RF**: `WiFi Analyzer`.

### MÓDULO NETWORK 3: Segurança em Redes WiFi
Este módulo foca na defesa de redes WiFi, com práticas modernas e conformidade.

##### Conteúdo Detalhado (Ordenado):
- **Arquitetura wireless: pessoal vs empresarial**: Configurações domésticas vs corporativas (ex.: RADIUS).
- **WPA3: SAE, proteção contra ataques**: Implementação de Simultaneous Authentication of Equals.
- **Autenticação 802.1X: RADIUS, EAP-TLS**: Configuração de autenticação corporativa.
- **Redes de visitantes: isolamento, portais cativos**: Criação de VLANs para visitantes.
- **Segmentação: VLANs, firewalls**: Configuração de VLANs (ex.: VLAN 20 para IoT).
- **Gerenciamento de RF: canais, potência**: Otimização de canais para evitar interferências.
- **Segurança física: proteção de APs**: Posicionamento e travas físicas para APs.
- **Monitoramento: Kismet, Wireshark**: Análise de tráfego WiFi com Kismet.
- **WIDS/WIPS: detecção de intrusão**: Configuração de sistemas como OpenWIPS-NG.
- **Políticas: filtragem de MAC, limites**: Restrição de acesso por MAC ou dispositivos.
- **Conformidade: PCI DSS, ISO 27001**: Requisitos para redes WiFi seguras.
- **Resposta a incidentes: forense WiFi**: Análise de logs para investigar ataques.
- **Melhores práticas: atualizações, senhas fortes**: Configuração de WPA3 e atualizações regulares.

##### Ferramentas Essenciais:
- **Monitoramento e Análise**: `Kismet`, `Wireshark`.
- **Sistemas de Detecção**: `OpenWIPS-NG` (ou similares para WIDS/WIPS).
- **Configuração de Rede**: Ferramentas de configuração de `VLANs` e `Firewalls` (ex: `iptables`, interfaces de roteadores/switches).

### MÓDULO NETWORK 4: Ataques de Negação de Serviço e Botnets
Este módulo cobre ataques DoS/DDoS e botnets, com foco em mitigação prática.

##### Conteúdo Detalhado (Ordenado):
- **Tipos de DoS: volumétrico, protocolo, aplicação**: Ataques como SYN flood (protocolo) e HTTP flood (aplicação).
- **SYN flood: esgotamento de recursos TCP**: Exploração de handshakes TCP incompletos.
- **UDP flood: amplificação**: Uso de pacotes UDP para sobrecarregar servidores.
- **Slowloris: HTTP lento**: Esgotamento de conexões web com requisições lentas.
- **Amplificação: DNS, NTP, Memcached**: Uso de servidores para amplificar tráfego (ex.: DNS amplification).
- **Botnets: arquitetura C&C, IRC, HTTP**: Estrutura de comando e controle (ex.: Mirai).
- **Criação de botnets: propagação via IoT**: Exploração de dispositivos como câmeras IP.
- **DDoS sob demanda: stressers/booters**: Análise de serviços como booter.xyz.
- **Detecção: análise de tráfego com Wireshark**: Identificação de picos de tráfego.
- **Mitigação: limitação de taxa, geo-blocking**: Configuração de firewalls para limitar tráfego.
- **Serviços de proteção: Cloudflare, AWS Shield**: Configuração de CDN para mitigar DDoS.
- **Resposta a incidentes: desvio de tráfego**: Uso de BGP para redirecionar tráfego.
- **Botnets P2P: descentralização**: Análise de botnets como Sality.
- **Aspectos legais: persecução de DDoS**: Leis como a Lei Carolina Dieckmann.

##### Ferramentas Essenciais:
- **Geração de Tráfego**: Ferramentas para gerar SYN/UDP floods (ex: `hping3`, `LOIC`).
- **Análise de Tráfego**: `Wireshark`.
- **Mitigação**: Ferramentas de configuração de `firewalls` (ex: `iptables`), serviços de proteção `Cloudflare`, `AWS Shield`.

### MÓDULO NETWORK 5: Ataques Man-in-the-Middle
Este módulo cobre ataques MITM, com Illuminary

##### Conteúdo Detalhado (Ordenado):
- **Fundamentos MITM: posicionamento, interceptação**: Como se posicionar entre vítima e destino.
- **ARP spoofing: arpspoof, Bettercap**: Envenenamento de tabelas ARP (ex.: bettercap -T target).
- **DHCP spoofing: servidores falsos**: Configuração de servidores DHCP maliciosos.
- **DNS spoofing: envenenamento de cache**: Redirecionamento de DNS com Responder.
- **SSL stripping: sslstrip, mitmproxy**: Remoção de HTTPS para capturar dados.
- **Bettercap: módulos, sniffing**: Uso de módulos como http.proxy e dns.spoof.
- **Responder: captura de hashes NTLM**: Exploração de credenciais Windows.
- **Ataques em switches: MAC flooding**: Sobrecarga de tabelas CAM em switches.
- **MITM wireless: Evil Twin**: Criação de APs falsos com hostapd.
- **Interceptação SSL/TLS: mitmproxy**: Configuração de proxies transparentes.
- **IPv6: ataques RA**: Exploração de anúncios de roteador IPv6.
- **BGP hijacking: manipulação de rotas**: Análise de ataques como o hijacking de 2018.
- **Detecção: HSTS, pinning de certificados**: Configuração de HSTS para prevenir SSL stripping.
- **Prevenção: segmentação, criptografia forte**: Uso de VLANs e TLS 1.3.
- **Aspectos legais: testes autorizados**: Limites éticos para ataques MITM.

##### Ferramentas Essenciais:
- **MITM**: `arpspoof`, `Bettercap`, `Responder`, `sslstrip`, `mitmproxy`, `hostapd` (para Evil Twin).




## TRILHA HACKING DE HARDWARE (VERMELHO)
*   **Pré-requisitos:** Conclusão da Trilha Principal, especialmente Linux e Python. Conhecimentos de programação em C são recomendados.

### MÓDULO HARDWARE 1: Fundamentos de Eletrônica
Este módulo introduz eletrônica, com laboratórios práticos para montagem e análise.

##### Conteúdo Detalhado (Ordenado):
- **Tensão, corrente, resistência: conceitos básicos**: Medições com multímetro (ex.: 5V em um LED).
- **Lei de Ohm: cálculos práticos**: Cálculo de resistores para circuitos (ex.: V=IR).
- **Componentes passivos: resistores, capacitores, indutores**: Função de cada componente (ex.: capacitor em filtro).
- **Componentes ativos: diodos, transistores**: Uso de diodos (ex.: 1N4007) e transistores (ex.: 2N2222).
- **Circuitos: série, paralelo**: Montagem de circuitos em protoboard.
- **Esquemas elétricos: leitura, símbolos**: Interpretação de diagramas (ex.: KiCad).
- **Multímetro: medições de tensão/corrente**: Uso prático em circuitos reais.
- **Protoboard: montagem prática**: Construção de um circuito LED simples.
- **Segurança: ESD, proteção**: Prevenção de descargas eletrostáticas.
- **PCBs: camadas, trilhas**: Análise de placas de circuito impresso.
- **Soldagem: técnicas, ferros de solda**: Soldagem de componentes em PCB.
- **Dessoldagem: sugador, malha**: Remoção de componentes com segurança.
- **Osciloscópio: análise de sinais**: Medição de formas de onda (ex.: onda quadrada).
- **Gerador de funções: sinais senoidais**: Criação de sinais para testes.
- **Circuitos integrados: 555, amplificadores**: Uso do CI 555 em temporizadores.

##### Ferramentas Essenciais:
- **Hardware**: `Multímetro`, `Protoboard`, `Ferro de Solda`, `Sugador de Solda`, `Osciloscópio`, `Gerador de Funções`.
- **Software**: `KiCad` (para esquemas elétricos e PCBs).

### MÓDULO HARDWARE 2: Gadgets para Pentest e Red Team
Este módulo foca em ferramentas físicas para pentest, com configurações práticas.

##### Conteúdo Detalhado (Ordenado):
- **Raspberry Pi: modelos, GPIO**: Configuração de um Pi 4 para pentest.
- **Kali Linux no Raspberry Pi: instalação**: Configuração do Kali com ferramentas de segurança.
- **Arduino: programação, sensores**: Criação de um sensor de movimento com Arduino.
- **ESP32: WiFi, projetos**: Desenvolvimento de um sniffer WiFi com ESP32.
- **USB Rubber Ducky: payloads**: Criação de payloads (ex.: abrir shell via USB).
- **WiFi Pineapple: ataques wireless**: Configuração de módulos como PineAP.
- **Keyloggers: PS/2, USB**: Configuração de keyloggers físicos.
- **Lockpicking: chaves de tensão**: Técnicas básicas de abertura de fechaduras.
- **Flipper Zero: RFID, NFC**: Clonagem de tags RFID com Flipper.
- **HackRF: rádio definido por software**: Captura de sinais com HackRF One.
- **RTL-SDR: escuta de frequências**: Escuta de rádio FM com RTL-SDR.
- **Proxmark3: clonagem RFID/NFC**: Clonagem de cartões MIFARE.
- **ChameleonMini: emulação NFC**: Emulação de tags NFC.
- **Câmeras ocultas: transmissão WiFi**: Configuração de câmeras para vigilância.
- **Bypass físico: shims, impacto**: Técnicas de bypass de fechaduras físicas.

##### Ferramentas Essenciais:
- **Placas de Desenvolvimento**: `Raspberry Pi`, `Arduino`, `ESP32`.
- **Dispositivos de Pentest**: `USB Rubber Ducky`, `WiFi Pineapple`, `Flipper Zero`, `HackRF`, `RTL-SDR`, `Proxmark3`, `ChameleonMini`.
- **Outros**: `Keyloggers físicos`, `Ferramentas de Lockpicking`.

### MÓDULO HARDWARE 3: Exploração de Jogos com Hardware
Este módulo cobre hacking de jogos, com foco em consoles e técnicas avançadas.

##### Conteúdo Detalhado (Ordenado):
- **Arquitetura de consoles: PS4, Xbox One**: Estrutura de CPUs, GPUs e memória.
- **Bootloaders: processo de inicialização**: Análise de bootloaders em consoles.
- **Segurança de cartuchos: chips de autenticação**: Exploração de chips como CIC.
- **Edição de saves: hexadecimal, Checksum**: Alteração de saves (ex.: Pokémon).
- **Softmodding: exploits de software**: Uso de exploits como WebKit no PS4.
- **Modchips: instalação, bypass**: Instalação de chips para desbloqueio.
- **Análise de rede: tráfego de jogos**: Captura de pacotes de jogos online.
- **JTAG/SWD: depuração de hardware**: Uso de JTAG para acessar memória.
- **Extração de NAND: ferramentas**: Leitura de memória flash com SPI.
- **Modificação de firmware: custom firmware**: Instalação de CFW em consoles.
- **Antitrapaça: detecção de cheats**: Análise de sistemas como VAC.
- **Glitching: tensão, clock**: Introdução de falhas para bypass de segurança.
- **Canal lateral: análise de energia**: Extração de chaves via consumo de energia.
- **Engenharia reversa: Ghidra, IDA**: Desmontagem de binários de jogos.
- **Aspectos legais: DMCA, EULA**: Leis aplicáveis ao hacking de jogos.

##### Ferramentas Essenciais:
- **Hardware**: `JTAG/SWD Debuggers`, `SPI Programmers`.
- **Software**: `Ghidra`, `IDA Pro` (para engenharia reversa), `Wireshark` (para análise de tráfego de rede).

### MÓDULO HARDWARE 4: Hacking de Hardware na Prática
Este módulo foca em técnicas avançadas de hacking de hardware.

##### Conteúdo Detalhado (Ordenado):
- **Análise de PCB: identificação de trilhas**: Uso de multímetro para mapear trilhas.
- **Componentes: marcações, datasheets**: Leitura de códigos (ex.: SMD codes).
- **Pontos de teste: continuidade**: Localização de pontos com multímetro.
- **UART: conexão serial, baud rate**: Acesso a UART com PuTTY.
- **I2C: leitura de EEPROM**: Acesso a memórias com Bus Pirate.
- **SPI: extração de flash**: Leitura de chips SPI com clipes.
- **Analisador lógico: decodificação**: Captura de sinais com Saleae Logic.
- **Extração de firmware: JTAG, bootloader**: Uso de OpenOCD para extração.
- **Binwalk: análise de firmware**: Extração de sistemas de arquivos (ex.: binwalk -e firmware.bin).
- **Depuração JTAG: varredura de limites**: Identificação de pontos JTAG.
- **Modificação de firmware: patching**: Aplicação de patches com Ghidra.
- **Chip-off: remoção de BGA**: Extração física de chips NAND.
- **Canal lateral: análise de energia**: Uso de ChipWhisperer para ataques.
- **Injeção de falhas: glitching laser**: Introdução de falhas para bypass.
- **IoT: exploração de roteadores**: Análise de roteadores com OpenWrt.

##### Ferramentas Essenciais:
- **Hardware**: `Multímetro`, `Bus Pirate`, `Saleae Logic` (Analisador Lógico), `JTAG Debuggers` (ex: `OpenOCD`), `ChipWhisperer`.
- **Software**: `PuTTY` (para UART), `Binwalk`, `Ghidra`.




## TRILHA WEB & CLOUD (ROXO)
*   **Pré-requisitos:** Conclusão da Trilha Principal, especialmente o Módulo 8 (Fundamentos de Segurança Web e Cloud).

### MÓDULO WEB 1: Ataques em Aplicações Web
Este módulo cobre ataques web, com foco no OWASP Top 10 e exploração prática.

##### Conteúdo Detalhado (Ordenado):
- **OWASP Top 10: A01-A10**: Estudo de vulnerabilidades como Broken Access Control e XSS.
- **Burp Suite: proxy, repeater, intruder**: Configuração do Burp para interceptar e manipular requisições.
- **OWASP ZAP: varredura automatizada**: Uso do ZAP para identificar vulnerabilidades.
- **SQL Injection: UNION, blind**: Exploração de injeções (ex.: \' UNION SELECT username, password --).
- **XSS: refletido, armazenado, DOM**: Injeção de scripts (ex.: <script>alert(\'XSS\')</script>).
- **CSRF: forjar requisições**: Criação de formulários maliciosos para ações não autorizadas.
- **Path traversal: acesso a arquivos**: Exploração (ex.: ../../etc/passwd).
- **Brute force: Hydra, Burp Intruder**: Ataques a formulários de login.
- **Sequestro de sessão: cookies**: Captura de session_id com XSS.
- **Broken Access Control: IDOR**: Acesso a recursos não autorizados (ex.: /user/123).
- **SQLMap: automação de injeções**: Uso do SQLMap (ex.: sqlmap -u url).
- **BeEF: exploração de XSS**: Controle de navegadores com BeEF.
- **XXE: SSRF, leitura de arquivos**: Exploração de XML External Entity.
- **Desserialização: Java, Python**: Exploração de objetos desserializados.
- **Injeção de comandos: execução cega**: Execução de comandos (ex.: ; whoami).
- **Web shells: PHP, ASP**: Upload de shells para controle remoto.
- **Payloads personalizados: desenvolvimento**: Criação de exploits para vulnerabilidades específicas.

##### Ferramentas Essenciais:
- **Proxies de Interceptação**: `Burp Suite`, `OWASP ZAP`.
- **SQL Injection**: `SQLMap`.
- **XSS Exploitation**: `BeEF`.
- **Brute Force**: `Hydra`, `Burp Intruder`.
- **Outras**: Ferramentas para `Path Traversal`, `XXE`, `Desserialização`, `Injeção de Comandos` (ex: `Netcat` para web shells).

### MÓDULO WEB 2: Pentest em Ambientes Cloud
Este módulo foca em segurança na nuvem, com práticas em AWS, Azure e GCP.

##### Conteúdo Detalhado (Ordenado):
- **Modelos de nuvem: IaaS, PaaS, SaaS**: Diferenças e responsabilidades (ex.: AWS EC2 vs Lambda).
- **AWS: IAM, S3, EC2**: Configuração segura de permissões e buckets.
- **Azure: Active Directory, VMs**: Gerenciamento de identidades e máquinas virtuais.
- **GCP: IAM, Cloud Storage**: Configuração de políticas de acesso.
- **Configurações incorretas: buckets públicos**: Identificação de S3 públicos (ex.: aws s3 ls).
- **APIs: REST, autenticação**: Testes de APIs com Postman.
- **Containers: Docker, Kubernetes**: Segurança de imagens Docker (ex.: Trivy).
- **Serverless: AWS Lambda, Azure Functions**: Configuração segura de funções.
- **ScoutSuite: auditoria de nuvem**: Relatórios de segurança para AWS/Azure/GCP.
- **Prowler: conformidade AWS**: Verificação de melhores práticas.
- **VPCs: segmentação de rede**: Configuração de redes privadas virtuais.
- **CloudTrail: monitoramento de logs**: Análise de logs para auditoria.
- **Ataques a armazenamento: exfiltração**: Extração de dados de buckets expostos.
- **Abuso de tokens: IAM**: Exploração de permissões excessivas.
- **Conformidade: GDPR, SOC 2**: Requisitos regulatórios para nuvem.
- **Kubernetes: Kube-Hunter**: Varredura de vulnerabilidades em clusters.

##### Ferramentas Essenciais:
- **Ferramentas CLI/SDK**: `aws cli`, `az cli`, `gcloud cli`.
- **Auditoria de Nuvem**: `ScoutSuite`, `Prowler`.
- **Segurança de Containers**: `Trivy`.
- **Segurança Kubernetes**: `Kube-Hunter`.
- **Testes de API**: `Postman`.

### MÓDULO WEB 3: Automação e Estratégias de Bug Bounty
Este módulo foca em bug bounty, com automação e redação de relatórios.

##### Conteúdo Detalhado (Ordenado):
- **Plataformas: HackerOne, Bugcrowd**: Escolha de programas com base em escopo.
- **Automação de reconhecimento: Nuclei**: Varreduras com templates (ex.: nuclei -t xss.yaml).
- **Rastreamento web: spiders**: Criação de spiders com Scrapy.
- **Parâmetros: Arjun, ParamSpider**: Descoberta de parâmetros ocultos.
- **Testes de API: REST, GraphQL**: Exploração de vulnerabilidades em APIs.
- **Automação: Python, Bash scripts**: Scripts para varreduras massivas.
- **Relatórios: impacto, recomendações**: Redação de relatórios para HackerOne.
- **PoC: vídeos, capturas**: Criação de provas de conceito visuais.
- **Comunicação: interação com empresas**: Melhores práticas para relatar bugs.
- **Apps móveis: análise de APK**: Extração de APIs com MobSF.
- **Gerenciamento de tempo: priorização**: Foco em alvos de alto impacto.
- **Networking: Twitter, Discord**: Participação em comunidades de bug bounty.
- **Divulgação responsável: ética**: Protocolos para relatar vulnerabilidades.

### MÓDULO WEB 4: Inteligência Artificial para Pentest Web
Este módulo explora IA em pentest, com aplicações práticas e éticas.

##### Conteúdo Detalhado (Ordenado):
- **Aprendizado de máquina: supervisionado, não supervisionado**: Conceitos de ML aplicados à segurança.
- **IA em cibersegurança: detecção, automação**: Uso de IA em SIEMs e scanners.
- **NLP: análise de logs**: Extração de padrões com spaCy.
- **Detecção de anomalias: Isolation Forest**: Identificação de tráfego anômalo.
- **Fuzzing com IA: algoritmos genéticos**: Geração de entradas de teste.
- **Bypass de WAF: payloads gerados por IA**: Criação de payloads com ML.
- **Ferramentas: TensorFlow, scikit-learn**: Desenvolvimento de modelos de IA.
- **Chatbots: injeção de prompts**: Exploração de chatbots como Grok.
- **Análise preditiva: previsão de ameaças**: Uso de modelos para prever ataques.
- **Red teaming: exemplos adversariais**: Criação de inputs para enganar IA.
- **Exploits automatizados: execução simbólica**: Desenvolvimento com angr.
- **Ética em IA: viés, privacidade**: Considerações éticas no uso de IA.
- **Computação quântica: impacto na cibersegurança**: Introdução a algoritmos quânticos.




## TRILHA MOBILE & SOCIAL (LARANJA)
*   **Pré-requisitos:** Conclusão da Trilha Principal. Conhecimentos de programação (Java/Kotlin) são recomendados para o desenvolvimento de malware.

### MÓDULO MOBILE 1: Pentest em Aplicativos Android
Este módulo cobre pentest em Android, com análise estática e dinâmica.

##### Conteúdo Detalhado (Ordenado):
- **Arquitetura Android: kernel, ART**: Estrutura do sistema Android.
- **APK: AndroidManifest.xml, dex**: Análise de componentes com apktool.
- **Análise estática: JADX, dex2jar**: Descompilação de APKs.
- **Análise dinâmica: ADB, emuladores**: Testes com Genymotion e ADB.
- **OWASP Mobile Top 10: M1-M10**: Vulnerabilidades como armazenamento inseguro.
- **Armazenamento: SharedPreferences, SQLite**: Análise de dados locais.
- **Rede: proxy, interceptação**: Uso de Burp para capturar tráfego.
- **WebView: injeção de scripts**: Exploração de WebViews vulneráveis.
- **Criptografia: algoritmos fracos**: Identificação de DES em APKs.
- **Intents: deep links**: Exploração de intents (ex.: intent://).
- **Frida: hooking de funções**: Manipulação de runtime com Frida.
- **SSL pinning: bypass com Frida**: Contorno de pinning de certificados.
- **Root detection: bypass**: Modificação de APKs para evitar detecção.
- **Código nativo: ARM, JNI**: Análise de bibliotecas nativas.
- **MobSF: análise automatizada**: Uso do Mobile Security Framework.
- **Depuração: gdbserver**: Depuração de apps com gdb.
- **Malware: sandbox, análise**: Execução em sandboxes como Cuckoo.

### MÓDULO MOBILE 2: Desenvolvimento de Malwares para Android
Este módulo foca no desenvolvimento de malwares, com ênfase em evasão.

##### Conteúdo Detalhado (Ordenado):
- **Desenvolvimento: Java, Kotlin**: Criação de apps com Android Studio.
- **Malware: trojans, spyware, ransomware**: Tipos e objetivos de malware.
- **Vetores: sideload, phishing**: Métodos de entrega (ex.: APK malicioso).
- **Payloads: droppers, esteganografia**: Uso de droppers para instalar malware.
- **Persistência: serviços, alarmes**: Configuração de serviços persistentes.
- **Exfiltração: contatos, SMS**: Extração de dados via HTTP.
- **C2: Tor, HTTP**: Comunicação com servidores de comando.
- **Carregamento dinâmico: DexClassLoader**: Execução de código dinâmico.
- **Ofuscação: ProGuard, R8**: Ofuscação de código para evitar análise.
- **Esteganografia: ocultação em imagens**: Esconder payloads em PNGs.
- **Evasão: detecção de emuladores**: Técnicas para evitar sandboxes.
- **Botnets: comandos remotos**: Integração em redes de bots.
- **Antivírus: bypass de assinaturas**: Modificação de código para evasão.
- **Malwares reais: Anubis, Cerberus**: Análise de malwares bancários.
- **Ética: pesquisa responsável**: Limites éticos para desenvolvimento.

### MÓDULO MOBILE 3: Técnicas de Phishing e Engenharia Social
Este módulo foca em engenharia social, com campanhas práticas e éticas.

##### Conteúdo Detalhado (Ordenado):
- **Psicologia: princípios de Cialdini**: Uso de autoridade, escassez, reciprocidade.
- **Ciclo de engenharia social: OSINT, pretexting**: Planejamento de ataques.
- **Pretexting: cenários convincentes**: Criação de narrativas (ex.: suporte técnico).
- **Phishing: e-mails, clonagem de sites**: Criação de e-mails com Gophish.
- **Spear phishing: ataques personalizados**: Uso de OSINT para direcionamento.
- **Vishing: chamadas VoIP**: Configuração de chamadas automáticas.
- **Smishing: SMS maliciosos**: Uso de ferramentas como SMS Bomber.
- **Engenharia social física: tailgating**: Técnicas de acesso físico.
- **Elicitação: extração de informações**: Métodos de conversa para obter dados.
- **Manipulação: urgência, medo**: Uso de gatilhos emocionais.
- **Bypass de SPF/DKIM: spoofing**: Contorno de proteções de e-mail.
- **Kits de phishing: SET, Gophish**: Configuração de campanhas automatizadas.
- **Redes sociais: perfis falsos**: Criação de perfis no LinkedIn.
- **Conscientização: simulações**: Treinamento de usuários com ataques simulados.
- **Métricas: taxas de cliques**: Avaliação de campanhas de phishing.
- **Aspectos legais: autorização**: Requisitos para testes éticos.




## TRILHA PROGRAMAÇÃO & EXPLORAÇÃO (AMARELO)
*   **Pré-requisitos:** Conclusão da Trilha Principal, especialmente Python.

### MÓDULO PROG 1: Fundamentos de C para Pentesters
Este módulo ensina C com foco em exploração de vulnerabilidades.

##### Conteúdo Detalhado (Ordenado):
- **Sintaxe C: tipos, variáveis, loops**: Estrutura básica de programas em C.
- **Funções: argumentos, retorno**: Criação de funções (ex.: int add(int a, int b)).
- **Ponteiros: aritmética, arrays**: Uso de ponteiros (ex.: *ptr = &var).
- **Estruturas: structs, unions**: Organização de dados com structs.
- **Arquivos: fopen, fwrite**: Manipulação de arquivos em C.
- **Memória: malloc, free**: Alocação dinâmica de memória.
- **Codificação segura: validação de entrada**: Prevenção de buffer overflows.
- **Buffer overflows: exploração na pilha**: Desenvolvimento de exploits simples.
- **Corrupção de memória: use-after-free**: Identificação de vulnerabilidades.
- **Depuração: GDB, AddressSanitizer**: Uso de GDB para encontrar erros.
- **Análise estática: Flawfinder**: Revisão de código para falhas.
- **Fuzzing: AFL, libFuzzer**: Testes automatizados de vulnerabilidades.
- **Shellcode: desenvolvimento**: Criação de shellcode em C.
- **Assembly: integração com C**: Uso de inline assembly.
- **Protecções: canários, ASLR**: Como funcionam e como contornar.
- **Auditoria: padrões de vulnerabilidade**: Identificação de erros comuns.
- **Multiplataforma: Windows vs Linux**: Diferenças em C entre sistemas.

### MÓDULO PROG 2: Pós-exploração Linux
Este módulo foca em técnicas de pós-exploração em Linux.

##### Conteúdo Detalhado (Ordenado):
- **Enumeração: /etc/passwd, /proc**: Coleta de informações do sistema.
- **Processos: ps, lsof, strace**: Análise de processos em execução.
- **Rede: netstat, ss, iptables**: Identificação de conexões e regras.
- **Scripts de enumeração: LinEnum, linuxprivchecker**: Automação de enumeração.
- **Escalação: SUID, sudoers**: Exploração de binários SUID (ex.: /usr/bin/find).
- **Exploits de kernel: Dirty COW**: Uso de exploits como CVE-2016-5195.
- **Persistência: cron, systemd**: Configuração de tarefas para acesso contínuo.
- **Chaves SSH: authorized_keys**: Adição de chaves para acesso remoto.
- **Backdoors: web shells, netcat**: Criação de shells reversos.
- **Exfiltração: scp, curl**: Transferência de dados para servidores externos.
- **Túneis DNS: iodine**: Comunicação oculta via DNS.
- **Antiforense: shred, logrotate**: Exclusão segura de rastros.
- **Movimentação lateral: SSH, smbexec**: Acesso a outros sistemas.
- **Fuga de containers: Docker breakout**: Exploração de containers mal configurados.
- **LOLBins: ferramentas nativas**: Uso de find, tar para ataques.

### MÓDULO PROG 3: Fundamentos de PowerShell para Pentesters
Este módulo ensina PowerShell com foco em red teaming.

##### Conteúdo Detalhado (Ordenado):
- **Cmdlets: Get-Process, Invoke-WebRequest**: Comandos básicos do PowerShell.
- **Políticas: bypass de execução**: Uso de Set-ExecutionPolicy Bypass.
- **Execução remota: Invoke-Command**: Execução em sistemas remotos.
- **Registro: persistência via reg add**: Configuração de chaves de registro.
- **WMI: ataques com Get-WmiObject**: Coleta de informações via WMI.
- **PowerShell Empire: ouvintes, stagers**: Configuração de C2 com Empire.
- **LOLBins: bitsadmin, certutil**: Uso de binários nativos do Windows.
- **Credenciais: Mimikatz, PowerView**: Extração de hashes NTLM.
- **Ofuscação: Invoke-Obfuscation**: Ofuscação de scripts PowerShell.
- **Bypass AMSI: patching**: Contorno da Antimalware Scan Interface.
- **Bypass ETW: manipulação de eventos**: Evitar logs de eventos.
- **Injeção: process hollowing**: Execução de código em memória.
- **Movimentação lateral: WMI, PSExec**: Acesso a outros sistemas.
- **Covenant: integração .NET**: Uso de Covenant para C2.
- **Modo restrito: bypass**: Contorno de restrições de linguagem.
- **Payloads: criptografia**: Criação de payloads ofuscados.
- **Logging: manipulação de logs**: Alteração de logs do Windows.

### MÓDULO PROG 4: Pós-exploração Windows e Active Directory
Este módulo cobre ataques em Windows/AD, com foco em técnicas avançadas.

##### Conteúdo Detalhado (Ordenado):
- **Active Directory: domínios, OUs**: Estrutura de AD e hierarquia.
- **Enumeração: PowerView, BloodHound**: Coleta de dados com PowerView.
- **Kerberos: autenticação, tickets**: Funcionamento do Kerberos.
- **Pass-the-Hash: NTLM**: Uso de hashes para acesso.
- **Pass-the-Ticket: TGT, TGS**: Reutilização de tickets Kerberos.
- **UAC: bypass com scripts**: Contorno do Controle de Conta de Usuário.
- **Contas de serviço: LocalSystem**: Exploração de contas privilegiadas.
- **GPOs: modificação de políticas**: Alteração de GPOs para escalação.
- **Kerberoasting: extração de TGS**: Quebra de tickets de serviço.
- **ASREPRoasting: contas sem pré-autenticação**: Exploração com GetNPUsers.
- **DCSync: replicação de diretório**: Extração de credenciais via replicação.
- **Golden Ticket: falsificação krbtgt**: Criação de tickets falsos.
- **Silver Ticket: tickets de serviço**: Exploração de serviços específicos.
- **Delegação: restrita, irrestrita**: Abuso de delegação para escalação.
- **ADCS: exploração de CA**: Ataques a autoridades certificadoras.
- **LAPS: bypass**: Contorno de senhas administrativas locais.

### MÓDULO PROG 5: Assembly e Desenvolvimento de Exploits
Este módulo foca em Assembly e exploração avançada.

##### Conteúdo Detalhado (Ordenado):
- **Arquitetura x86/x64: registros, flags**: Estrutura de processadores Intel.
- **Assembly: NASM, sintaxe**: Escrita de programas com NASM.
- **Pilha: push, pop, call**: Gerenciamento da pilha em Assembly.
- **Memória: pilha, heap, segmentos**: Layout de memória de processos.
- **Depuradores: GDB, x64dbg**: Depuração de binários.
- **Buffer overflow: injeção de código**: Exploração de overflows na pilha.
- **Shellcode: chamadas de sistema**: Criação de shellcode (ex.: execve).
- **Format string: leitura/escrita**: Exploração de vulnerabilidades de formato.
- **ROP: gadgets, cadeias**: Uso de Return-Oriented Programming.
- **ASLR: bypass via vazamentos**: Contorno de randomização de endereços.
- **DEP: return-to-libc**: Uso de bibliotecas para evitar DEP.
- **Canários: previsão, bypass**: Contorno de canários de pilha.
- **Heap: use-after-free, double-free**: Exploração de vulnerabilidades no heap.
- **Fuzzing: afl-fuzz, honggfuzz**: Testes automatizados de binários.
- **Kernel: bypass de SMEP**: Exploração de vulnerabilidades no kernel.
- **Ghidra: engenharia reversa**: Desmontagem de binários.




## TRILHA MALWARE & EVASÃO (PRETO)
*   **Pré-requisitos:** Conclusão da Trilha Principal e da Trilha de Programação & Exploração (AMARELO).

### MÓDULO MALWARE 1: Análise e Desenvolvimento de Malwares
Este módulo cobre análise e criação de malwares, com foco em engenharia reversa.

##### Conteúdo Detalhado (Ordenado):
- **Malware: vírus, worms, trojans**: Características e exemplos (ex.: WannaCry).
- **Ambiente: REMnux, Flare VM**: Configuração de VMs para análise.
- **Análise estática: strings, entropia**: Extração de strings com strings2.
- **PE: seções, imports, exports**: Análise de arquivos PE com PEiD.
- **Desmontagem: Ghidra, Radare2**: Desmontagem de binários.
- **Análise dinâmica: Process Monitor**: Monitoramento de processos em tempo real.
- **Droppers: entrega de payloads**: Criação de droppers em Python.
- **Persistência: registro, tarefas**: Configuração de persistência no Windows.
- **C2: HTTP, DNS**: Comunicação com servidores de comando.
- **Ofuscação: criptografia de strings**: Uso de XOR para ofuscação.
- **Evasão: detecção de sandboxes**: Técnicas para evitar Cuckoo.
- **Empacotamento: UPX, Themida**: Uso de empacotadores para proteção.
- **Ransomware: criptografia AES**: Desenvolvimento de ransomware simulado.
- **Rootkits: hooking de SSDT**: Ocultação de processos no kernel.
- **Forense: Volatility, Rekall**: Análise de despejos de memória.
- **Malwares reais: Emotet, TrickBot**: Estudo de malwares modernos.

### MÓDULO MALWARE 2: Técnicas de Evasão de Antivírus e EDR
Este módulo foca em técnicas de evasão de sistemas de detecção.

##### Conteúdo Detalhado (Ordenado):
- **AV: assinaturas, heurísticas**: Como antivírus detectam malware.
- **Polimorfismo: mutação de código**: Alteração dinâmica de payloads.
- **Ofuscação: código morto, junk code**: Inserção de código inútil.
- **Empacotamento: execução em memória**: Uso de Veil ou Themida.
- **Malware sem arquivo: PowerShell, WMI**: Scripts sem toque no disco.
- **Injeção: process hollowing, DLL injection**: Injeção em processos legítimos.
- **API hooking: bypass**: Chamadas diretas ao kernel.
- **AMSI: patching de memória**: Contorno da Antimalware Scan Interface.
- **ETW: bypass de logs**: Evitar logs de eventos do Windows.
- **LOLBins: certutil, regsvr32**: Uso de binários nativos.
- **DLL hijacking: ordem de busca**: Exploração de carregamento de DLLs.
- **Sandbox: detecção de VMs**: Técnicas para evitar sandboxes.
- **C2: DNS tunneling, steganografia**: Comunicação oculta com servidores.
- **Codificação: base64, XOR**: Codificação de payloads.
- **EDR: bypass de minifiltros**: Contorno de sistemas como CrowdStrike.




## Lógica de Progressão e Recomendações de Estudo

Este roadmap foi estruturado para proporcionar uma jornada de aprendizado progressiva e coerente em cibersegurança. A ideia é construir uma base sólida antes de se aprofundar em áreas mais especializadas.

### Lógica de Progressão:
- **Nível 1 (Fundamentos Essenciais):** Começa com a introdução à cibersegurança, seguida por Linux e Redes. Estes são os pilares para qualquer área da cibersegurança. É crucial dominar esses conceitos antes de avançar.
- **Nível 2 (Ferramentas e Técnicas Fundamentais):** Introduz Python como uma ferramenta essencial para automação e desenvolvimento, seguido por Reconhecimento (uma fase inicial de qualquer pentest) e Criptografia/Senhas. O conhecimento de Python permite uma aplicação mais prática dos conceitos de reconhecimento e criptografia.
- **Nível 3 (Aplicação e Defesa):** Aborda Privacidade e Anonimato, Fundamentos de Segurança Web e Cloud, e Metodologias de Pentest. Este nível consolida o conhecimento, aplicando-o em cenários mais amplos e introduzindo a importância da ética e das metodologias.
- **Trilhas Especializadas:** Cada trilha especializada (Redes, Hardware, Web & Cloud, Mobile & Social, Programação & Exploração, Malware & Evasão) possui pré-requisitos claros da trilha principal. Isso garante que o aluno tenha a base necessária antes de se aprofundar em um nicho específico. A ordem dos módulos dentro de cada trilha também segue uma lógica progressiva, do básico ao avançado dentro daquela especialidade.

### Recomendações de Tempo de Estudo:
O tempo de estudo pode variar significativamente de pessoa para pessoa, dependendo da dedicação, experiência prévia e ritmo de aprendizado. No entanto, uma estimativa geral pode ser:

-   **Trilha Principal:** 6 a 12 meses (aproximadamente 1-2 meses por módulo, com dedicação de 10-15 horas/semana).
-   **Trilhas Especializadas:** 3 a 6 meses por trilha (aproximadamente 1-2 meses por módulo, com dedicação de 10-15 horas/semana).

**Dicas:**
-   **Consistência é Chave:** Estude regularmente, mesmo que por períodos curtos.
-   **Prática Ativa:** Não apenas leia, mas pratique. Configure laboratórios, resolva desafios (CTFs), e desenvolva seus próprios projetos.
-   **Revisão:** Revise periodicamente os conceitos para solidificar o aprendizado.
-   **Comunidade:** Participe de comunidades online, fóruns e grupos de estudo para trocar conhecimentos e tirar dúvidas.

### Sugestões de Projetos Práticos:

Para cada módulo, tente aplicar o conhecimento em projetos práticos. Isso não só solidifica o aprendizado, mas também cria um portfólio valioso.

-   **Módulo 2 (Linux/Shell):** Crie scripts Bash para automatizar tarefas de administração de sistema ou para realizar varreduras básicas de rede.
-   **Módulo 3 (Redes):** Configure uma rede virtual com diferentes sub-redes, firewalls e VLANs. Use Wireshark para analisar o tráfego.
-   **Módulo 4 (Python):** Desenvolva um pequeno scanner de portas, um script para analisar logs ou uma ferramenta simples de web scraping.
-   **Módulo 5 (Reconhecimento):** Realize um OSINT completo sobre uma empresa fictícia ou um alvo de teste autorizado, utilizando as ferramentas e técnicas aprendidas.
-   **Módulo 6 (Criptografia):** Implemente um algoritmo de criptografia simples em Python ou C. Crie um sistema de gerenciamento de senhas básico.
-   **Módulo 7 (Privacidade/Anonimato):** Configure um ambiente de navegação anônima usando Tor e VPNs. Analise metadados de arquivos.
-   **Módulo 8 (Web/Cloud):** Crie uma aplicação web simples e tente identificar e corrigir vulnerabilidades OWASP Top 10. Configure um bucket S3 seguro na AWS.
-   **Módulo 9 (Metodologias):** Escolha um alvo de teste (com permissão) e aplique uma metodologia de pentest completa, desde o reconhecimento até a elaboração do relatório.

**Para as Trilhas Especializadas:**
-   **Redes:** Realize um pentest completo em uma rede local simulada, incluindo ataques WiFi e MITM.
-   **Hardware:** Monte um pequeno circuito eletrônico, ou utilize um Raspberry Pi para criar um dispositivo de segurança (ex: honeypot).
-   **Web & Cloud:** Desenvolva um script para automatizar a busca por vulnerabilidades em aplicações web ou participe de programas de Bug Bounty.
-   **Mobile & Social:** Analise um APK de um aplicativo Android (com permissão) em busca de vulnerabilidades. Crie uma campanha de phishing simulada para conscientização.
-   **Programação & Exploração:** Desenvolva um exploit para uma vulnerabilidade conhecida (em ambiente controlado) ou crie um shellcode simples.
-   **Malware & Evasão:** Analise um malware real (em ambiente seguro) ou desenvolva um pequeno programa que tente evadir a detecção de antivírus (apenas para fins educacionais e em ambiente isolado).

Lembre-se: a cibersegurança é um campo em constante evolução. O aprendizado contínuo e a prática são essenciais para se manter atualizado e eficaz.

