#!/usr/bin/env bash
# ==============================================================================
# run_pipeline.sh - Inicializador do SecScannerPipeline DBSeller
# Cria venv (se não existir), instala dependências e executa o pipeline.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="$SCRIPT_DIR/.venv"

echo "================================================================================"
echo " [SecScannerPipeline] Preparando ambiente de execução..."
echo "================================================================================"

# 1. Verifica/Cria o Virtualenv
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Criando ambiente virtual Python (.venv)..."
    python3 -m venv "$VENV_DIR"
fi

# 2. Ativa o Virtualenv
source "$VENV_DIR/bin/activate"

# 3. Garante pip atualizado e dependências instaladas
echo "[+] Verificando dependências Python..."
pip install --upgrade pip --quiet
pip install -r "$SCRIPT_DIR/requirements.txt" --quiet

echo "[✓] Ambiente pronto com sucesso!"
echo "================================================================================"

# 4. Modo de Execução: Foreground ou Background
if [ "$1" == "--bg" ] || [ "$1" == "--background" ]; then
    shift
    LOG_FILE="$SCRIPT_DIR/logs/execution_$(date +%Y-%m-%d_%H-%M-%S).log"
    mkdir -p "$SCRIPT_DIR/logs"
    echo "[+] Iniciando em SEGUNDO PLANO (Background)..."
    echo "[+] Arquivo de log: $LOG_FILE"
    setsid "$VENV_DIR/bin/python3" -u "$SCRIPT_DIR/pipeline.py" "$@" > "$LOG_FILE" 2>&1 &
    PID=$!
    echo "[✓] Processo iniciado com PID: $PID"
    echo "[*] Para acompanhar o log em tempo real: tail -f $LOG_FILE"
else
    echo "[+] Iniciando em PRIMEIRO PLANO (Acompanhamento direto)..."
    echo "================================================================================"
    "$VENV_DIR/bin/python3" "$SCRIPT_DIR/pipeline.py" "$@"
fi
