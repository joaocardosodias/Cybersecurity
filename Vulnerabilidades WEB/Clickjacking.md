# Clickjacking: Desconstruindo o Ataque de Redirecionamento de UI

## Seção 1: Introdução ao Clickjacking - A Arte da Decepção

### 1.1. Definindo a Ameaça: Mais do que Apenas um Clique Sequestrado

**Clickjacking**, ou Ataque de Redirecionamento de Interface do Usuário (UI Redress Attack), é uma técnica maliciosa do lado do cliente que engana usuários para clicarem em elementos diferentes do que percebem, podendo expor informações confidenciais ou comprometer seus dispositivos. O ataque utiliza camadas transparentes ou opacas para ocultar elementos maliciosos sob uma interface aparentemente legítima, sequestrando cliques destinados a uma página isca e redirecionando-os para uma página alvo, possivelmente de outro domínio.

Diferente de vulnerabilidades como Injeção de SQL ou Cross-Site Scripting (XSS), o Clickjacking explora a camada de renderização visual do navegador, transformando HTML e CSS em armas que quebram a confiança entre o usuário e a interface visual. Ele manipula a percepção de uma interface bidimensional, enquanto a realidade é uma pilha tridimensional de camadas, com a camada superior capturando interações.

### 1.2. Contexto Histórico e Surgimento Inicial

O termo **Clickjacking** foi criado em 2008 por Jeremiah Grossman e Robert Hansen, descrevendo um ataque contra o Adobe Flash Player. Esse ataque exemplifica o problema do "deputado confuso", onde um sistema é enganado para usar indevidamente sua autoridade. Casos iniciais incluem:

- **Ataque ao Adobe Flash**: Usuários foram enganados para alterar configurações de segurança do Flash via um *iframe* invisível, permitindo acesso a microfone e câmera.
- **Worm do Twitter (2009)**: Um ataque induzia usuários a retuitar um link malicioso, propagando-se viralmente.

## Seção 2: A Anatomia de um Ataque de Clickjacking - Uma Análise Técnica Aprofundada

### 2.1. O Veículo Principal: O Elemento `<iframe>`

O ataque utiliza elementos como `<iframe>`, `<frame>`, `<object>` ou `<embed>` para incorporar uma página alvo em um site isca malicioso. A vulnerabilidade está na "enquadrabilidade" (*frameability*) da página alvo — qualquer página carregável em um *iframe* é potencialmente vulnerável. A defesa, portanto, foca em controlar onde uma página pode ser renderizada, não apenas na validação de entradas.

### 2.2. A Arte da Invisibilidade: Manipulação de CSS

O sucesso do ataque depende de propriedades CSS para criar a ilusão:

- **`opacity`**: Define o *iframe* como quase invisível (ex.: `opacity: 0.0001`), ocultando a página alvo enquanto mantém sua interatividade.
- **`z-index`**: Posiciona o *iframe* invisível acima da isca, garantindo que receba os cliques.
- **`position`**: Alinha precisamente o elemento clicável do *iframe* sobre a isca visível.

### 2.3. Passo a Passo do Ataque: Excluindo a Conta de um Usuário

Exemplo prático de ataque:

1. **Preparação do Invasor**: Cria uma página isca com conteúdo atraente (ex.: "Clique aqui").
2. **Enquadrando o Alvo**: Incorpora a página alvo (ex.: `https://site-vulneravel.com/minha-conta`) em um *iframe* invisível.
3. **Criação da Sobreposição**:

```html
<head>
  <style>
    iframe {
      position: relative;
      width: 500px;
      height: 700px;
      opacity: 0.0001;
      z-index: 2;
    }
    div {
      position: absolute;
      top: 300px;
      left: 60px;
      z-index: 1;
    }
  </style>
</head>
<body>
  <div id="decoy_website">Clique aqui</div>
  <iframe id="target_website" src="https://site-vulneravel.com/minha-conta"></iframe>
</body>
```

4. **Engenharia Social**: A vítima, autenticada no site alvo, é levada à página isca via *phishing*.
5. **Ação Não Intencional**: O clique na isca é registrado no botão "Excluir conta" do *iframe*, deletando a conta sem consentimento. O ataque contorna proteções CSRF, pois a requisição é legítima.

## Seção 3: Espectro da Malícia: Variantes e Objetivos do Clickjacking

### 3.1. Manipulação de Mídias Sociais: Likejacking

O **Likejacking** sequestra cliques em botões de mídias sociais (ex.: "Curtir" do Facebook). Um *iframe* invisível faz o usuário "curtir" uma página maliciosa, inflando popularidade ou espalhando golpes.

### 3.2. Sequestro de Teclas e Dados

- **Sequestro de Teclas**: Sobreposição de campos de entrada invisíveis captura credenciais digitadas.
- **Cookiejacking**: Engana o usuário para arrastar cookies de sessão, enviando-os ao invasor.
- **Filejacking**: Induz cliques em botões de upload, acessando o sistema de arquivos local.

### 3.3. Manipulação Avançada de UI e Temporal

- **Cursorjacking**: Altera a posição do cursor, enganando o usuário para clicar em elementos maliciosos.
- **Clickjacking de Múltiplas Etapas**: Requer sequência de cliques, com reposicionamento dinâmico do *iframe*.

Qualquer interação de UI (cliques, teclas, arrastar) é explorável se a página for enquadrável.

## Seção 4: Impacto e Consequências no Mundo Real

### 4.1. Ações Não Autorizadas e Fraude Financeira

O Clickjacking pode forçar ações como compras, transferências bancárias ou exclusão de dados, aproveitando sessões autenticadas. Isso causa perdas financeiras e danos à reputação.

### 4.2. Invasão de Privacidade e Roubo de Credenciais

- **Roubo de Credenciais**: Formulários falsos capturam logins.
- **Estudo de Caso: Adobe Flash**: Usuários enganados ativaram microfone e câmera via configurações do Flash, permitindo vigilância.

### 4.3. Propagação Viral e Engenharia Social

- **Estudo de Caso: Worm do Twitter (2009)**: O worm "Don't Click" usava Clickjacking para retuitar links maliciosos, espalhando-se rapidamente.

## Seção 5: Uma Estratégia de Defesa em Múltiplas Camadas

### 5.1. Defesas Primárias do Lado do Servidor: Controlando a Incorporação de Frames

- **Content Security Policy (CSP) frame-ancestors**:
  - **`'none'`**: Impede enquadramento (equivalente a `X-Frame-Options: DENY`).
  - **`'self'`**: Permite enquadramento pela mesma origem (equivalente a `X-Frame-Options: SAMEORIGIN`).
  - **Lista de fontes**: Permite domínios específicos (ex.: `https://parceiro-confiavel.com`).

- **X-Frame-Options (XFO)**:
  - **`DENY`**: Proíbe enquadramento.
  - **`SAMEORIGIN`**: Permite mesma origem.
  - **`ALLOW-FROM`**: Obsoleto, com suporte inconsistente.

**Comparação**:

| Característica           | X-Frame-Options                     | CSP frame-ancestors                 |
|--------------------------|-------------------------------------|-------------------------------------|
| Objetivo                 | Prevenir Clickjacking               | Prevenir Clickjacking               |
| Lista Branca             | Limitada (ALLOW-FROM obsoleto)      | Flexível (múltiplos domínios)       |
| Relatório de Violações   | Não                                 | Sim (via report-to/report-uri)      |
| Suporte do Navegador     | Bom para legados                    | Excelente em navegadores modernos   |
| Granularidade            | Baixa (DENY, SAMEORIGIN)            | Alta (none, self, host-source)      |
| Recomendação             | Fallback para legados               | Padrão moderno                      |

### 5.2. Defesas Secundárias e Complementares

- **Atributo de Cookie SameSite**:
  - `Strict` ou `Lax` impede o envio de cookies em *iframes* de origem cruzada, invalidando ações não autenticadas.
- **Frame-Busting Scripts** (Legado):
  - Exemplo:

```javascript
if (top !== self) {
  top.location = self.location;
}
```

  - **Bypass**: Atributo `sandbox="allow-forms"` no *iframe* bloqueia acesso a `window.top`.
  - Não confiável devido a vulnerabilidades.

## Seção 6: Conclusão

### 6.1. Recapitulação da Ameaça

O Clickjacking explora a confiança do usuário na interface, usando tecnologias web padrão para induzir ações não intencionais. As consequências vão de manipulação de mídias sociais a roubo de credenciais e invasão de privacidade. A vulnerabilidade raiz é a enquadrabilidade de uma página.

### 6.2. A Primazia das Defesas do Lado do Servidor

Defesas modernas priorizam políticas do lado do servidor. A diretiva **CSP frame-ancestors** é a principal defesa, com controle granular e relatórios. **X-Frame-Options** serve como *fallback* para navegadores legados. Essas medidas tornam o Clickjacking significativamente mais difícil de explorar.