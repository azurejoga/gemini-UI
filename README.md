
# Gemini UI 🤖

Uma interface web moderna e responsiva para interagir com o **Gemini CLI** da Google através de uma aplicação Flask em Python.

![Status](https://img.shields.io/badge/status-funcionando-success)
![Python](https://img.shields.io/badge/python-3.11-blue)
![Flask](https://img.shields.io/badge/flask-3.0.0-lightgrey)
![Node.js](https://img.shields.io/badge/node.js-20.19.3-green)

## 🚀 Início Rápido

### 1. Configure suas Variáveis de Ambiente

Copie o arquivo `.env.example` para `.env`:

```bash
cp .env.example .env
```

Edite o arquivo `.env` e adicione sua chave de API do Google AI Studio:

1. Acesse: **https://aistudio.google.com/app/apikey**
2. Faça login com sua conta Google
3. Clique em **"Create API Key"**
4. Cole a chave no arquivo `.env`:

```env
GEMINI_API_KEY=yor_api_key
SESSION_SECRET=seu_secret_key_aqui
```

### 2. Instale as Dependências

```bash
pip install -r requirements.txt
```

### 3. Execute a Aplicação

```bash
python app.py
```

A aplicação estará disponível em `http://0.0.0.0:5000`

## ✨ Funcionalidades

### Interface e Experiência
- 💬 **Interface de chat moderna** - Design inspirado no Google Gemini
- 📱 **Responsivo** - Funciona em desktop e mobile
- 🎨 **Temas claro/escuro** - Alterne entre temas com um clique
- ⚡ **Respostas em tempo real** - Comunicação rápida com o Gemini CLI

### Gerenciamento de Conversas
- 💾 **Histórico persistente** - Conversas salvas localmente (localStorage)
- 📝 **Sessões de conversação** - Múltiplas sessões isoladas
- 🗑️ **Limpeza de histórico** - Botão para iniciar nova conversa
- 📤 **Exportação de conversas** - Exporte em formato JSON

### Análise de Arquivos
- 📎 **Upload de arquivos** - Anexe qualquer tipo de arquivo
- 🖼️ **Análise multimodal** - Imagens, documentos, código, etc.
- 🔄 **Gerenciamento de anexos** - Remova ou substitua arquivos facilmente
- 📁 **Compatibilidade total** - Suporta todos os formatos aceitos pelo Gemini

### Templates e Produtividade
- 📋 **Templates de prompts** - Crie e gerencie templates personalizados via `gemini.md`
- ⚡ **Criação rápida** - Botão dedicado para criar templates
- 🎯 **Prompts pré-configurados** - Exemplos para análise de código, debugging, etc.

### Performance e Segurança
- 🚀 **Sistema de cache** - Respostas armazenadas para prompts repetidos
- 🔒 **Seguro** - Proteção contra XSS, validação de entrada, timeouts
- ∞ **Sem limites** - Envie prompts de qualquer tamanho
- ⏱️ **Timeout configurável** - 60 segundos para evitar travamentos

### Instalação Automática
- 🔧 **Auto-setup** - Verifica e instala Node.js, npm e Gemini CLI automaticamente
- ✅ **Pronto para usar** - Configuração automática na primeira execução

## 🛠️ Tecnologias

- **Backend**: Python 3.11 + Flask 3.0.0
- **IA**: Gemini CLI (via subprocess)
- **Frontend**: HTML5 + CSS3 + JavaScript Vanilla
- **Runtime**: Node.js 20.x (para Gemini CLI)
- **Storage**: localStorage (frontend) + memória (backend)

## 📖 Como Usar

### Chat Básico
1. Digite sua pergunta no campo de texto
2. Pressione **Enter** ou clique no botão de envio
3. Aguarde a resposta do Gemini
4. Continue a conversa!

### Anexar Arquivos
1. Clique no botão **📎 Anexar arquivo**
2. Selecione qualquer arquivo (imagem, PDF, código, etc.)
3. Digite um prompt descrevendo o que deseja fazer com o arquivo
4. Exemplo: "Descreva esta imagem", "Analise este código", "Resuma este documento"
5. Para remover/trocar: clique em **❌ Remover anexo** e anexe outro

### Usar Templates
1. Clique no botão **📋 Templates**
2. Você será solicitado a descrever o template desejado
3. Digite sua descrição (ex: "Template para análise de código Python")
4. O sistema criará automaticamente o arquivo `gemini.md` com seu template
5. Use o template digitando o prompt na caixa de chat

### Alternar Tema
- Clique no botão **☀️/🌙** no cabeçalho
- O tema atual será exibido no tooltip ("Tema: Escuro" ou "Tema: Claro")

### Exportar Conversa
1. Clique no botão **💾 Exportar**
2. Sua conversa será baixada em formato JSON
3. Contém todas as mensagens da sessão atual

**Dicas:**
- Use **Shift + Enter** para adicionar uma nova linha sem enviar
- **Sem limite de caracteres** - Envie prompts de qualquer tamanho
- O indicador verde mostra que está conectado
- Clique no **🗑️ ícone de lixeira** para limpar o histórico
- Suas conversas são salvas automaticamente (F5 seguro)

## 📂 Estrutura do Projeto

```
.
├── app.py                # Aplicação Flask principal
├── templates/
│   └── index.html       # Interface do chat
├── static/
│   ├── style.css        # Estilos CSS (tema claro/escuro)
│   └── script.js        # Lógica JavaScript
├── requirements.txt     # Dependências Python
├── .env.example         # Exemplo de variáveis de ambiente
├── .env                 # Suas variáveis de ambiente (não versionar)
├── gemini.md            # Templates de prompts (criado automaticamente)
└── README.md            # Esta documentação
```

## 🔧 Endpoints da API

### `GET /`
Retorna a interface web principal.

### `POST /ask`
Processa um prompt através do Gemini CLI.

**Request:**
```json
{
  "prompt": "Explique o que é Python",
  "file_path": "arquivo.jpg" // opcional
}
```

**Response:**
```json
{
  "response": "Python é uma linguagem de programação...",
  "prompt": "Explique o que é Python",
  "session_id": "uuid-da-sessao",
  "cached": false
}
```

### `POST /upload_file`
Faz upload de um arquivo para análise.

**Request:** FormData com arquivo
**Response:**
```json
{
  "filename": "nome_do_arquivo",
  "filepath": "caminho_relativo"
}
```

### `GET /sessions`
Lista todas as sessões do usuário.

### `POST /sessions`
Cria uma nova sessão de conversação.

### `GET /templates`
Retorna o conteúdo do arquivo `gemini.md`.

### `GET /export/<session_id>?format=json`
Exporta uma sessão específica.

### `GET /health`
Verifica o status da aplicação e do Gemini CLI.

## 🔐 Segurança

- ✅ Sanitização de entrada no backend e frontend
- ✅ Proteção contra XSS usando `textContent` e `MarkupSafe.escape`
- ✅ Timeout de 60 segundos para evitar travamentos
- ✅ Validação em múltiplas camadas
- ✅ Arquivos enviados com nomes únicos (UUID)
- ✅ Cache de respostas para melhor performance

## 🐛 Solução de Problemas

### "Gemini CLI não está autenticado"
**Solução:** Configure sua `GOOGLE_API_KEY` no arquivo `.env`.

### "Tempo limite excedido"
**Solução:** O prompt é muito complexo. Tente algo mais simples ou aumente o `GEMINI_TIMEOUT` em `app.py`.

### "Gemini CLI não encontrado"
**Solução:** A aplicação tentará instalar automaticamente na primeira execução. Se falhar, execute manualmente:
```bash
npm install -g @google/gemini-cli
```

### Interface não carrega
**Solução:** Verifique se a aplicação está rodando na porta 5000 e se as variáveis de ambiente estão configuradas.

### Arquivo não é anexado
**Solução:** Certifique-se de que o arquivo foi enviado com sucesso (mensagem de confirmação aparece). Depois, digite um prompt descrevendo o que deseja fazer com o arquivo.

## 📝 Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto (use `.env.example` como referência):

- `GEMINI_API_KEY=yor_api_key` - **OBRIGATÓRIO** - Chave de API do Google AI Studio
- `SESSION_SECRET` - Chave secreta para sessões Flask (gere uma aleatória)

**Exemplo:**
```env
GEMINI_API_KEY=yor_api_key=AIzaSyC...seu_key_aqui
SESSION_SECRET=sua_chave_secreta_aleatoria_aqui
```

## 📄 Licença

Este projeto foi criado para uso educacional e demonstração de integração com Gemini CLI.

---

**Desenvolvido com ❤️ para a comunidade**
