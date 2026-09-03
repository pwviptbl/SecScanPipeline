#!/usr/bin/env bash
# ==============================================================================
# run_web.sh - Inicializador do Painel Web SecScannerPipeline
# DBSeller Serviços de Informática
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="$SCRIPT_DIR/.venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Criando ambiente virtual Python (.venv)..."
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

pip install flask requests jinja2 weasyprint --quiet

PORT="${PORT:-8088}"

if [ "$1" == "--bg" ] || [ "$1" == "--background" ]; then
    LOG_FILE="$SCRIPT_DIR/logs/web_$(date +%Y-%m-%d).log"
    mkdir -p "$SCRIPT_DIR/logs"
    echo "[+] Iniciando Painel Web em SEGUNDO PLANO na porta $PORT..."
    echo "[+] Log do servidor: $LOG_FILE"
    setsid "$VENV_DIR/bin/python3" -u "$SCRIPT_DIR/app.py" >> "$LOG_FILE" 2>&1 &
    PID=$!
    echo "[✓] Servidor iniciado com PID: $PID"
    echo "[*] Acesse: http://localhost:$PORT"
else
    echo "[+] Iniciando Painel Web em PRIMEIRO PLANO na porta $PORT..."
    echo "[*] Acesse: http://localhost:$PORT"
    "$VENV_DIR/bin/python3" "$SCRIPT_DIR/app.py"
fi
