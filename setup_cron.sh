#!/usr/bin/env bash
# ==============================================================================
# setup_cron.sh - Configurador de Agendamento Automático (Cron) do Pipeline
# DBSeller Serviços de Informática
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run_pipeline.sh"
CRON_JOB_TAG="# SECSCANNER_PIPELINE_DAILY_SCHEDULE"

usage() {
    echo "================================================================================"
    echo "  SecScannerPipeline - Gerenciador de Agendamento (Cron)"
    echo "================================================================================"
    echo "Uso: $0 [opções]"
    echo ""
    echo "Opções de Agendamento:"
    echo "  --time HH:MM        Define um horário específico diário (ex: --time 23:30)"
    echo "  --install           Instala agendamento no horário padrão (02:00 AM todo dia)"
    echo "  --install-2x        Instala agendamento 2x ao dia (02:00 AM e 14:00 PM)"
    echo ""
    echo "Opções de Consulta e Remoção:"
    echo "  --status            Exibe o agendamento atual configurado no crontab"
    echo "  --remove            Remove o agendamento do crontab"
    echo "  --help              Exibe esta mensagem de ajuda"
    echo "================================================================================"
}

action="${1:---install}"

case "$action" in
    --time)
        TIME_ARG="$2"
        if [[ ! "$TIME_ARG" =~ ^([0-9]{1,2}):([0-9]{2})$ ]]; then
            echo "[!] Formato de horário inválido: '$TIME_ARG'. Use o formato HH:MM (ex: 23:00 ou 03:30)."
            exit 1
        fi
        HOUR="${BASH_REMATCH[1]}"
        MINUTE="${BASH_REMATCH[2]}"
        
        CRON_SCHEDULE="$MINUTE $HOUR * * *"
        CRON_CMD="$RUNNER --bg > /dev/null 2>&1 $CRON_JOB_TAG"
        
        echo "[+] Configurando agendamento diário para as ${TIME_ARG}..."
        (crontab -l 2>/dev/null | grep -v "$CRON_JOB_TAG" || true; echo "$CRON_SCHEDULE $CRON_CMD") | crontab -
        echo "[✓] Agendamento configurado com sucesso!"
        echo "[*] O pipeline rodará automaticamente todos os dias às ${TIME_ARG}."
        ;;
    --install)
        echo "[+] Instalando agendamento diário padrão (02:00 AM)..."
        CRON_CMD="$RUNNER --bg > /dev/null 2>&1 $CRON_JOB_TAG"
        (crontab -l 2>/dev/null | grep -v "$CRON_JOB_TAG" || true; echo "0 2 * * * $CRON_CMD") | crontab -
        echo "[✓] Agendamento configurado com sucesso!"
        echo "[*] O pipeline rodará diariamente às 02:00 AM."
        ;;
    --install-2x)
        echo "[+] Instalando agendamento redundante 2x ao dia (02:00 e 14:00)..."
        CRON_CMD="$RUNNER --bg > /dev/null 2>&1 $CRON_JOB_TAG"
        (crontab -l 2>/dev/null | grep -v "$CRON_JOB_TAG" || true; echo "0 2,14 * * * $CRON_CMD") | crontab -
        echo "[✓] Agendamento configurado com sucesso para 02:00 e 14:00 diariamente!"
        ;;
    --status)
        echo "=== Status do Crontab para o Pipeline ==="
        CURRENT_CRON=$(crontab -l 2>/dev/null | grep "$CRON_JOB_TAG" || true)
        if [ -n "$CURRENT_CRON" ]; then
            echo "[✓] Agendamento ativo:"
            echo "    $CURRENT_CRON"
        else
            echo "[!] Nenhum agendamento ativo encontrado para este pipeline."
        fi
        ;;
    --remove)
        echo "[+] Removendo agendamento do Crontab..."
        crontab -l 2>/dev/null | grep -v "$CRON_JOB_TAG" | crontab - || true
        echo "[✓] Agendamento removido com sucesso."
        ;;
    --help|-h)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac
