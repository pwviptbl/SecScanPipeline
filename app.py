#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SecScannerPipeline - Painel Web de Monitoramento e Gestão de Evidências
DBSeller Serviços de Informática
"""

import os
import sys
import json
import zipfile
import calendar
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash

from db import init_db, get_connection, get_monthly_matrix, sync_existing_evidences
from report_generator import generate_pdf_report, MONTH_NAMES_PT

BASE_DIR = Path(__file__).resolve().parent
EVIDENCIAS_DIR = BASE_DIR / "evidencias"
CONFIG_FILE = BASE_DIR / "config" / "targets.json"

app = Flask(__name__)
app.secret_key = "dbseller-secscanner-portal-secret"

def load_targets():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"clientes": []}

@app.route("/")
def index():
    sync_existing_evidences()
    targets_data = load_targets()
    clientes = targets_data.get("clientes", [])
    
    # Parâmetros de filtro
    client_id = request.args.get("client", "Niteroi")
    now = datetime.now()
    year = int(request.args.get("year", now.year))
    month = int(request.args.get("month", now.month))
    
    _, num_days = calendar.monthrange(year, month)
    days_range = list(range(1, num_days + 1))
    
    matrix = get_monthly_matrix(client_id, year, month)
    
    # Se uma aplicação não tiver scans ainda, inclui ela vazia a partir do targets.json
    client_obj = next((c for c in clientes if c["id"] == client_id), None)
    if client_obj:
        existing_prods = {p["name"] for p in matrix}
        for p in client_obj.get("produtos", []):
            if p["nome"] not in existing_prods:
                matrix.append({
                    "name": p["nome"],
                    "tools": {"nmap": {}, "nikto": {}, "owasp_zap": {}}
                })
                
    # Ordena por nome da aplicação
    matrix = sorted(matrix, key=lambda x: x["name"])
    
    # Calcula KPIs do mês
    total_checks = 0
    success_checks = 0
    error_checks = 0
    for prod in matrix:
        for tool, days in prod["tools"].items():
            for d, data in days.items():
                total_checks += 1
                if data["status"] == "SUCCESS":
                    success_checks += 1
                else:
                    error_checks += 1

    compliance_pct = round((success_checks / total_checks * 100), 1) if total_checks > 0 else 100.0

    return render_template(
        "index.html",
        clientes=clientes,
        client_id=client_id,
        year=year,
        month=month,
        month_name=MONTH_NAMES_PT.get(month, f"Mês {month:02d}"),
        days_range=days_range,
        matrix=matrix,
        total_checks=total_checks,
        success_checks=success_checks,
        error_checks=error_checks,
        compliance_pct=compliance_pct,
        now=now
    )

@app.route("/api/scan-detail")
def scan_detail():
    client_id = request.args.get("client")
    product_name = request.args.get("product")
    tool = request.args.get("tool")
    year = int(request.args.get("year"))
    month = int(request.args.get("month"))
    day = int(request.args.get("day"))
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM scan_executions
        WHERE client_id = ? AND product_name = ? AND tool = ? AND year = ? AND month = ? AND day = ?
        ORDER BY executed_at DESC LIMIT 1
    """, (client_id, product_name, tool, year, month, day))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"found": False})
        
    return jsonify({
        "found": True,
        "product_name": row["product_name"],
        "tool": row["tool"],
        "status": row["status"],
        "target_url": row["target_url"],
        "executed_at": row["executed_at"],
        "duration_seconds": row["duration_seconds"],
        "evidence_path": row["evidence_path"],
        "log_output": row["log_output"]
    })

@app.route("/api/generate-pdf")
def api_generate_pdf():
    client_id = request.args.get("client", "Niteroi")
    year = int(request.args.get("year", datetime.now().year))
    month = int(request.args.get("month", datetime.now().month))
    
    pdf_path = generate_pdf_report(client_id, year, month)
    filename = Path(pdf_path).name
    return send_file(pdf_path, as_attachment=True, download_name=filename, mimetype="application/pdf")

@app.route("/api/export-zip")
def api_export_zip():
    """
    Exporta evidências em arquivo ZIP:
    - scope: 'all' (tudo), 'month' (todo o mês), 'product_month' (aplicação no mês), 'product_day' (aplicação no dia)
    """
    scope = request.args.get("scope", "month")
    client_id = request.args.get("client", "Niteroi")
    product = request.args.get("product", "")
    year = request.args.get("year", datetime.now().strftime("%Y"))
    month = request.args.get("month", datetime.now().strftime("%m"))
    day = request.args.get("day", "")
    
    # Formata mês com 2 dígitos
    if month.isdigit():
        month = f"{int(month):02d}"
    if day.isdigit():
        day = f"{int(day):02d}"
        
    temp_zip = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    zip_path = temp_zip.name
    temp_zip.close()
    
    zip_filename = f"Evidencias_{client_id}"
    
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        if scope == "all":
            zip_filename = f"Evidencias_Todas_Aplicacoes_Consolidado.zip"
            for root, _, files in os.walk(EVIDENCIAS_DIR):
                for file in files:
                    full_path = Path(root) / file
                    rel_path = full_path.relative_to(EVIDENCIAS_DIR)
                    zf.write(full_path, arcname=str(rel_path))
                    
        elif scope == "product_day" and product and day:
            target_path = EVIDENCIAS_DIR / client_id / product / str(year) / str(month) / str(day)
            zip_filename = f"Evidencias_{client_id}_{product}_{year}_{month}_{day}.zip"
            if target_path.exists():
                for root, _, files in os.walk(target_path):
                    for file in files:
                        full_path = Path(root) / file
                        rel_path = full_path.relative_to(EVIDENCIAS_DIR)
                        zf.write(full_path, arcname=str(rel_path))
                        
        elif scope == "product_month" and product:
            target_path = EVIDENCIAS_DIR / client_id / product / str(year) / str(month)
            zip_filename = f"Evidencias_{client_id}_{product}_{year}_{month}.zip"
            if target_path.exists():
                for root, _, files in os.walk(target_path):
                    for file in files:
                        full_path = Path(root) / file
                        rel_path = full_path.relative_to(EVIDENCIAS_DIR)
                        zf.write(full_path, arcname=str(rel_path))
                        
        else: # scope == 'month'
            zip_filename = f"Evidencias_{client_id}_{year}_{month}_Todos_Produtos.zip"
            client_path = EVIDENCIAS_DIR / client_id
            if client_path.exists():
                for prod_dir in client_path.iterdir():
                    if not prod_dir.is_dir(): continue
                    target_month = prod_dir / str(year) / str(month)
                    if target_month.exists():
                        for root, _, files in os.walk(target_month):
                            for file in files:
                                full_path = Path(root) / file
                                rel_path = full_path.relative_to(EVIDENCIAS_DIR)
                                zf.write(full_path, arcname=str(rel_path))

    return send_file(zip_path, as_attachment=True, download_name=zip_filename, mimetype="application/zip")

@app.route("/api/run-pipeline", methods=["POST"])
def api_run_pipeline():
    """
    Aciona a execução do pipeline de scans completo em background.
    """
    try:
        runner_sh = BASE_DIR / "run_pipeline.sh"
        subprocess.Popen([str(runner_sh), "--bg"], cwd=str(BASE_DIR))
        return jsonify({"success": True, "message": "Pipeline completo iniciado com sucesso em segundo plano!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro ao iniciar pipeline: {e}"}), 500

@app.route("/api/rerun-scan", methods=["POST"])
def api_rerun_scan():
    """
    Re-executa o scan apenas de um produto ou ferramenta específica.
    """
    try:
        data = request.get_json(silent=True) or request.form or {}
        product = data.get("product")
        tool = data.get("tool")
        client = data.get("client")

        runner_sh = BASE_DIR / "run_pipeline.sh"
        cmd = [str(runner_sh), "--bg"]
        if product:
            cmd.extend(["--product", product])
        if tool:
            cmd.extend(["--tool", tool])
        if client:
            cmd.extend(["--client", client])

        subprocess.Popen(cmd, cwd=str(BASE_DIR))
        return jsonify({
            "success": True, 
            "message": f"Re-execução iniciada para a aplicação '{product}' ({tool or 'todas as ferramentas'})!"
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro ao re-executar scan: {e}"}), 500

@app.route("/logs")
def view_logs():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM scan_executions
        ORDER BY executed_at DESC LIMIT 100
    """)
    rows = cursor.fetchall()
    conn.close()
    return render_template("logs.html", logs=rows)

if __name__ == "__main__":
    init_db()
    sync_existing_evidences()
    port = int(os.environ.get("PORT", 8088))
    print(f"[*] Iniciando Portal SecScannerPipeline na porta {port}...")
    print(f"[*] Acesse: http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
