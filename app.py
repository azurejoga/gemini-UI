import os
import subprocess
import json
import logging
from flask import Flask, render_template, request, jsonify, session, Response
from markupsafe import escape
from dotenv import load_dotenv
from datetime import datetime
import uuid

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret-key-change-in-production')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Sessões em memória
SESSIONS_STORAGE = {}

# Cache de respostas
RESPONSE_CACHE = {}

def get_cache_key(prompt):
    return hash(prompt.strip().lower())

GEMINI_TIMEOUT = 60

# Flag para controlar se já verificamos as dependências
DEPENDENCIES_CHECKED = False

def check_and_install_dependencies():
    """Verifica e instala Node.js/npm e Gemini CLI se necessário"""
    global DEPENDENCIES_CHECKED

    if DEPENDENCIES_CHECKED:
        return

    logger.info("Verificando dependências...")

    # Verificar Gemini CLI
    try:
        result = subprocess.run(['gemini', '--version'], capture_output=True, timeout=5)
        if result.returncode == 0:
            logger.info(f"Gemini CLI encontrado: {result.stdout.decode().strip()}")
            DEPENDENCIES_CHECKED = True
            return
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.warning("Gemini CLI não encontrado, tentando instalar...")

    # Tentar instalar Gemini CLI
    try:
        logger.info("Instalando @google/gemini-cli...")
        result = subprocess.run(
            ['npm', 'install', '-g', '@google/gemini-cli'],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode == 0:
            logger.info("Gemini CLI instalado com sucesso!")
            DEPENDENCIES_CHECKED = True
        else:
            logger.error(f"Erro ao instalar Gemini CLI: {result.stderr}")
    except Exception as e:
        logger.error(f"Erro ao tentar instalar Gemini CLI: {str(e)}")

    DEPENDENCIES_CHECKED = True

@app.route('/')
def index():
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    return render_template('index.html')

@app.route('/upload_file', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Nenhum arquivo foi enviado'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'Arquivo sem nome'}), 400

        filename = f"{uuid.uuid4().hex}_{file.filename}"
        filepath = filename
        file.save(filepath)

        logger.info(f"Arquivo salvo: {filepath}")

        return jsonify({
            'filename': filename,
            'filepath': filepath
        }), 200

    except Exception as e:
        logger.error(f"Erro ao fazer upload de arquivo: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/ask_stream', methods=['POST'])
def ask_stream():
    """Endpoint para streaming via Server-Sent Events"""
    try:
        check_and_install_dependencies()

        data = request.get_json()

        if not data or 'prompt' not in data:
            return jsonify({'error': 'Prompt é obrigatório'}), 400

        prompt = data.get('prompt', '').strip()
        file_path = data.get('file_path')

        if not prompt:
            return jsonify({'error': 'Prompt não pode estar vazio'}), 400

        sanitized_prompt = escape(prompt)
        session_id = session.get('session_id', str(uuid.uuid4()))

        if session_id not in SESSIONS_STORAGE:
            SESSIONS_STORAGE[session_id] = []

        logger.info(f"Processando prompt: {sanitized_prompt[:100]}...")

        # Verificar cache
        cache_key = get_cache_key(prompt)
        if cache_key in RESPONSE_CACHE:
            logger.info("Resposta recuperada do cache")
            cached_response = RESPONSE_CACHE[cache_key]

            SESSIONS_STORAGE[session_id].append({
                'type': 'user',
                'content': str(sanitized_prompt),
                'timestamp': datetime.now().isoformat()
            })
            SESSIONS_STORAGE[session_id].append({
                'type': 'assistant',
                'content': cached_response,
                'timestamp': datetime.now().isoformat(),
                'cached': True
            })

            return jsonify({
                'response': cached_response,
                'cached': True
            }), 200

        try:
            env = os.environ.copy()
            api_key = env.get('GEMINI_API_KEY') or env.get('GOOGLE_API_KEY')
            if api_key:
                env['GEMINI_API_KEY'] = api_key
            else:
                return jsonify({
                    'error': 'API Key não configurada. Configure GOOGLE_API_KEY no arquivo .env'
                }), 401

            cmd = ['gemini', '-p', prompt]

            if file_path and os.path.exists(file_path):
                logger.info(f"Arquivo disponível para análise: {file_path}")

            # Executar comando
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=GEMINI_TIMEOUT,
                check=False,
                env=env
            )

            if result.returncode != 0:
                error_msg = result.stderr if result.stderr else 'Erro ao executar Gemini CLI'
                logger.error(f"Gemini CLI error: {error_msg}")

                if 'authentication' in error_msg.lower() or 'api key' in error_msg.lower():
                    return jsonify({
                        'error': 'Gemini CLI não está autenticado. Configure GOOGLE_API_KEY.',
                        'details': error_msg
                    }), 401

                return jsonify({
                    'error': 'Erro ao processar a solicitação',
                    'details': error_msg
                }), 500

            gemini_response = result.stdout

            # Garantir UTF-8
            if isinstance(gemini_response, bytes):
                gemini_response = gemini_response.decode('utf-8', errors='replace')

            logger.info(f"Resposta recebida: {str(gemini_response)[:100]}...")

            # Salvar no cache
            RESPONSE_CACHE[cache_key] = gemini_response

            # Salvar na sessão
            SESSIONS_STORAGE[session_id].append({
                'type': 'user',
                'content': str(sanitized_prompt),
                'timestamp': datetime.now().isoformat()
            })
            SESSIONS_STORAGE[session_id].append({
                'type': 'assistant',
                'content': gemini_response,
                'timestamp': datetime.now().isoformat()
            })

            return jsonify({
                'response': gemini_response
            }), 200

        except subprocess.TimeoutExpired:
            logger.error("Gemini CLI timeout")
            return jsonify({'error': 'Tempo limite excedido. Tente um prompt mais curto.'}), 504

        except FileNotFoundError:
            logger.error("Gemini CLI not found")
            return jsonify({
                'error': 'Gemini CLI não encontrado. Certifique-se de que está instalado.',
                'hint': 'Execute: npm install -g @google/gemini-cli'
            }), 500

    except Exception as e:
        logger.error(f"Erro inesperado: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor', 'details': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    try:
        result = subprocess.run(
            ['gemini', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        gemini_version = result.stdout.strip() if result.returncode == 0 else 'não disponível'
    except:
        gemini_version = 'não disponível'

    return jsonify({
        'status': 'ok',
        'gemini_cli_version': gemini_version
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)