const chatContainer = document.getElementById('chatContainer');
const chatForm = document.getElementById('chatForm');
const promptInput = document.getElementById('promptInput');
const sendButton = document.getElementById('sendButton');
const charCount = document.getElementById('charCount');
const statusText = document.querySelector('.status-text');
const statusDot = document.querySelector('.status-dot');

let isProcessing = false;
const STORAGE_KEY = 'gemini-chat-history';

const typingIndicator = document.getElementById('typingIndicator');

function showTypingIndicator() {
    if (typingIndicator) {
        typingIndicator.style.display = 'block';
    }
}

function hideTypingIndicator() {
    if (typingIndicator) {
        typingIndicator.style.display = 'none';
    }
}

function saveToLocalStorage(messages) {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(messages));
    } catch (error) {
        console.error('Erro ao salvar no localStorage:', error);
    }
}

function loadFromLocalStorage() {
    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        return stored ? JSON.parse(stored) : [];
    } catch (error) {
        console.error('Erro ao carregar do localStorage:', error);
        return [];
    }
}

function getAllMessages() {
    const messages = [];
    const messageElements = chatContainer.querySelectorAll('.message');
    messageElements.forEach(el => {
        const type = el.classList.contains('user') ? 'user' :
                     el.classList.contains('assistant') ? 'assistant' : 'error';
        const messageContent = el.querySelector('.message-content');

        let content;
        if (type === 'assistant') {
            content = messageContent.getAttribute('data-raw-text') || messageContent.textContent;
        } else {
            content = messageContent.textContent;
        }

        messages.push({ type, content });
    });
    return messages;
}

function updateCharCount() {
    const count = promptInput.value.length;
    charCount.textContent = count;
    charCount.style.color = 'var(--text-secondary)';
}

function autoResizeTextarea() {
    promptInput.style.height = 'auto';
    promptInput.style.height = Math.min(promptInput.scrollHeight, 150) + 'px';
}

promptInput.addEventListener('input', () => {
    updateCharCount();
    autoResizeTextarea();
});

promptInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        chatForm.dispatchEvent(new Event('submit'));
    }
});

function removeWelcomeMessage() {
    const welcomeMsg = document.querySelector('.welcome-message');
    if (welcomeMsg) {
        welcomeMsg.remove();
    }
}

function addMessage(content, type = 'user', saveToStorage = true) {
    removeWelcomeMessage();

    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;

    const iconLetter = type === 'user' ? 'V' : type === 'assistant' ? 'G' : '!';
    const label = type === 'user' ? 'Você' : type === 'assistant' ? 'Gemini' : 'Erro';

    const messageHeader = document.createElement('div');
    messageHeader.className = 'message-header';

    const messageIcon = document.createElement('div');
    messageIcon.className = 'message-icon';
    messageIcon.textContent = iconLetter;

    const messageLabel = document.createElement('span');
    messageLabel.className = 'message-label';
    messageLabel.textContent = label;

    messageHeader.appendChild(messageIcon);
    messageHeader.appendChild(messageLabel);

    const messageContent = document.createElement('div');
    messageContent.className = 'message-content';

    const contentStr = typeof content === 'string' ? content : String(content);

    if (type === 'assistant' && typeof marked !== 'undefined') {
        try {
            const htmlContent = marked.parse(contentStr);
            messageContent.innerHTML = htmlContent;
            messageContent.classList.add('markdown-rendered');
            messageContent.setAttribute('data-raw-text', contentStr);
        } catch (e) {
            console.error('Erro ao renderizar markdown:', e);
            messageContent.textContent = contentStr;
        }
    } else {
        messageContent.textContent = contentStr;
    }

    messageDiv.appendChild(messageHeader);
    messageDiv.appendChild(messageContent);

    chatContainer.appendChild(messageDiv);
    chatContainer.scrollTop = chatContainer.scrollHeight;

    if (saveToStorage) {
        const messages = getAllMessages();
        saveToLocalStorage(messages);
    }
}

function showLoading() {
    removeWelcomeMessage();

    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'loading';
    loadingDiv.id = 'loadingIndicator';

    const messageHeader = document.createElement('div');
    messageHeader.className = 'message-header';

    const messageIcon = document.createElement('div');
    messageIcon.className = 'message-icon';
    messageIcon.textContent = 'G';

    const messageLabel = document.createElement('span');
    messageLabel.className = 'message-label';
    messageLabel.textContent = 'Gemini';

    messageHeader.appendChild(messageIcon);
    messageHeader.appendChild(messageLabel);

    const loadingDots = document.createElement('div');
    loadingDots.className = 'loading-dots';

    for (let i = 0; i < 3; i++) {
        const dot = document.createElement('span');
        loadingDots.appendChild(dot);
    }

    loadingDiv.appendChild(messageHeader);
    loadingDiv.appendChild(loadingDots);

    chatContainer.appendChild(loadingDiv);
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

function removeLoading() {
    const loadingIndicator = document.getElementById('loadingIndicator');
    if (loadingIndicator) {
        loadingIndicator.remove();
    }
}

function setStatus(online) {
    if (online) {
        statusText.textContent = 'Conectado';
        statusDot.style.background = 'var(--success-color)';
    } else {
        statusText.textContent = 'Desconectado';
        statusDot.style.background = 'var(--error-color)';
    }
}

async function checkHealth() {
    try {
        const response = await fetch('/health');
        const data = await response.json();
        setStatus(data.status === 'ok');
    } catch (error) {
        setStatus(false);
    }
}

function loadChatHistory() {
    const messages = loadFromLocalStorage();
    if (messages.length > 0) {
        removeWelcomeMessage();
        messages.forEach(msg => {
            addMessage(msg.content, msg.type, false);
        });
    }
}

chatForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    if (isProcessing) return;

    const prompt = promptInput.value.trim();

    if (!prompt) return;

    isProcessing = true;
    sendButton.disabled = true;

    const displayMessage = selectedFile ? `${prompt}\n📎 ${selectedFile.name}` : prompt;
    addMessage(displayMessage, 'user');

    promptInput.value = '';
    promptInput.style.height = 'auto';
    updateCharCount();

    showLoading();
    showTypingIndicator();

    try {
        let finalPrompt = prompt;
        let uploadedFilePath = null;

        // Se tem arquivo anexado, faz upload primeiro
        if (selectedFile) {
            const formData = new FormData();
            formData.append('file', selectedFile);

            const uploadResponse = await fetch('/upload_file', {
                method: 'POST',
                body: formData
            });

            const uploadData = await uploadResponse.json();

            if (uploadResponse.ok) {
                uploadedFilePath = uploadData.filename;
                finalPrompt = `${prompt}\n\nArquivo disponível para análise: ${uploadData.filename}`;
            } else {
                removeLoading();
                hideTypingIndicator();
                addMessage('Erro ao fazer upload do arquivo: ' + uploadData.error, 'error');
                isProcessing = false;
                sendButton.disabled = false;
                return;
            }
        }

        // Enviar via HTTP
        const response = await fetch('/ask_stream', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                prompt: finalPrompt,
                file_path: uploadedFilePath
            })
        });

        const data = await response.json();

        removeLoading();
        hideTypingIndicator();

        if (response.ok) {
            addMessage(data.response, 'assistant');
        } else {
            addMessage(data.error || 'Erro ao processar solicitação', 'error');
        }

        // Limpar arquivo após envio
        selectedFile = null;
        fileInput.value = '';
        updateFilePreview();

        isProcessing = false;
        sendButton.disabled = false;
        promptInput.focus();

    } catch (error) {
        removeLoading();
        hideTypingIndicator();
        addMessage('Erro de conexão com o servidor. Tente novamente.', 'error');
        console.error('Erro:', error);
        isProcessing = false;
        sendButton.disabled = false;
    }
});

function clearHistory() {
    if (confirm('Tem certeza que deseja limpar todo o histórico de conversas?')) {
        localStorage.removeItem(STORAGE_KEY);
        chatContainer.innerHTML = '<div class="welcome-message"><h2>Olá! 👋</h2><p>Sou a interface web do Gemini CLI. Como posso ajudá-lo hoje?</p></div>';
    }
}

const clearHistoryBtn = document.getElementById('clearHistoryBtn');
if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', clearHistory);
}

// Tema escuro/claro
const themeToggleBtn = document.getElementById('themeToggleBtn');
const THEME_KEY = 'gemini-theme';

function updateThemeButton(theme) {
    const icon = themeToggleBtn.querySelector('svg');
    if (theme === 'dark') {
        icon.innerHTML = '<path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>';
        themeToggleBtn.title = 'Tema: Escuro (clique para claro)';
    } else {
        icon.innerHTML = '<path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>';
        themeToggleBtn.title = 'Tema: Claro (clique para escuro)';
    }
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
    updateThemeButton(theme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
}

if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', toggleTheme);
}

const savedTheme = localStorage.getItem(THEME_KEY) || 'light';
setTheme(savedTheme);

// Templates
const templatesBtn = document.getElementById('templatesBtn');
if (templatesBtn) {
    templatesBtn.addEventListener('click', () => {
        const templatePrompt = 'Crie um gemini.md com o seguinte:\nDescreva abaixo: ';
        promptInput.value = templatePrompt;
        promptInput.focus();

        promptInput.setSelectionRange(templatePrompt.length, templatePrompt.length);

        updateCharCount();
        autoResizeTextarea();
    });
}

// Exportação
const exportBtn = document.getElementById('exportBtn');
if (exportBtn) {
    exportBtn.addEventListener('click', async () => {
        try {
            const messages = getAllMessages();
            const dataStr = JSON.stringify({
                messages: messages,
                exported_at: new Date().toISOString()
            }, null, 2);

            const dataBlob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(dataBlob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `gemini-chat-${Date.now()}.json`;
            link.click();
            URL.revokeObjectURL(url);
        } catch (error) {
            console.error('Erro ao exportar:', error);
            addMessage('Erro ao exportar conversa', 'error');
        }
    });
}

// Upload de arquivo
const fileButton = document.getElementById('fileButton');
const fileInput = document.getElementById('fileInput');
const filePreview = document.getElementById('filePreview');
let selectedFile = null;

function updateFilePreview() {
    if (selectedFile) {
        filePreview.innerHTML = `
            <span style="color: var(--success-color);">📎 ${selectedFile.name}</span>
            <button type="button" id="removeFileBtn" style="margin-left: 8px; padding: 2px 8px; background: var(--error-color); color: white; border: none; border-radius: 4px; cursor: pointer;">Remover</button>
        `;

        const removeBtn = document.getElementById('removeFileBtn');
        if (removeBtn) {
            removeBtn.addEventListener('click', () => {
                selectedFile = null;
                fileInput.value = '';
                filePreview.innerHTML = '';
            });
        }
    } else {
        filePreview.innerHTML = '';
    }
}

if (fileButton && fileInput) {
    fileButton.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            selectedFile = file;
            updateFilePreview();
        }
    });
}

loadChatHistory();
checkHealth();
setInterval(checkHealth, 30000);
promptInput.focus();