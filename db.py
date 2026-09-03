#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de Banco de Dados e Rastreamento de Execução de Scans
SQLite portável em data/scanner.db
"""

import sqlite3
import os
import re
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "scanner.db"
EVIDENCIAS_DIR = BASE_DIR / "evidencias"

def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_executions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        product_name TEXT NOT NULL,
        target_url TEXT,
        target_host TEXT,
        year INTEGER NOT NULL,
        month INTEGER NOT NULL,
        day INTEGER NOT NULL,
        tool TEXT NOT NULL,
        status TEXT NOT NULL, /* 'SUCCESS', 'ERROR', 'RUNNING' */
        evidence_path TEXT,
        log_output TEXT,
        duration_seconds REAL DEFAULT 0,
        executed_at DATETIME NOT NULL
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_executions (year, month, day);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_prod ON scan_executions (client_id, product_name);")
    conn.commit()
    conn.close()

def record_scan_result(client_id, product_name, target_url, target_host, year, month, day, tool, status, evidence_path=None, log_output=None, duration_seconds=0):
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Atualiza ou insere novo registro para o dia/ferramenta
    cursor.execute("""
        INSERT INTO scan_executions (
            client_id, product_name, target_url, target_host,
            year, month, day, tool, status, evidence_path,
            log_output, duration_seconds, executed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        client_id, product_name, target_url, target_host,
        int(year), int(month), int(day), tool, status, evidence_path,
        log_output, duration_seconds, now_str
    ))
    conn.commit()
    conn.close()

def get_monthly_matrix(client_id, year, month):
    """
    Retorna a matriz de execução dos dias do mês para o cliente selecionado.
    Estrutura: {
       'products': [
           {
               'name': 'Ecidade',
               'tools': {
                   'nmap': { 1: 'SUCCESS', 2: 'SUCCESS', ... },
                   'nikto': { ... },
                   'owasp_zap': { ... }
               }
           }
       ]
    }
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT product_name, tool, day, status, log_output, evidence_path, MAX(executed_at) as latest_exec
        FROM scan_executions
        WHERE client_id = ? AND year = ? AND month = ?
        GROUP BY product_name, tool, day
        ORDER BY product_name, tool, day
    """, (client_id, int(year), int(month)))
    
    rows = cursor.fetchall()
    conn.close()
    
    products_map = {}
    for r in rows:
        prod = r['product_name']
        tool = r['tool']
        day = int(r['day'])
        status = r['status']
        log_out = r['log_output']
        ev_path = r['evidence_path']
        
        if prod not in products_map:
            products_map[prod] = {
                'name': prod,
                'tools': {
                    'nmap': {},
                    'nikto': {},
                    'owasp_zap': {}
                }
            }
        
        if tool in products_map[prod]['tools']:
            products_map[prod]['tools'][tool][day] = {
                'status': status,
                'log': log_out,
                'evidence': ev_path
            }
            
    return list(products_map.values())

def sync_existing_evidences():
    """
    Varre a pasta de evidências e popula o banco com os scans já executados no passado.
    """
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    
    if not EVIDENCIAS_DIR.exists():
        conn.close()
        return

    for client_dir in EVIDENCIAS_DIR.iterdir():
        if not client_dir.is_dir(): continue
        client_id = client_dir.name
        
        for prod_dir in client_dir.iterdir():
            if not prod_dir.is_dir(): continue
            prod_name = prod_dir.name
            
            for year_dir in prod_dir.iterdir():
                if not year_dir.is_dir() or not year_dir.name.isdigit(): continue
                year = int(year_dir.name)
                
                for month_dir in year_dir.iterdir():
                    if not month_dir.is_dir() or not month_dir.name.isdigit(): continue
                    month = int(month_dir.name)
                    
                    for day_dir in month_dir.iterdir():
                        if not day_dir.is_dir() or not day_dir.name.isdigit(): continue
                        day = int(day_dir.name)
                        
                        files = list(day_dir.iterdir())
                        tools_found = {}
                        
                        for f in files:
                            if f.name.startswith("nmap_") and f.suffix == ".xml" and f.stat().st_size > 0:
                                tools_found['nmap'] = str(f.relative_to(BASE_DIR))
                            elif f.name.startswith("nikto_") and f.suffix in [".xml", ".html", ".htm"] and f.stat().st_size > 0:
                                tools_found['nikto'] = str(f.relative_to(BASE_DIR))
                            elif f.name.startswith("zap_") and f.suffix in [".xml", ".html", ".json"] and f.stat().st_size > 0:
                                tools_found['owasp_zap'] = str(f.relative_to(BASE_DIR))
                        
                        for tool_name, ev_path in tools_found.items():
                            cursor.execute("""
                                SELECT id, status FROM scan_executions 
                                WHERE client_id = ? AND product_name = ? AND year = ? AND month = ? AND day = ? AND tool = ?
                            """, (client_id, prod_name, year, month, day, tool_name))
                            existing_row = cursor.fetchone()
                            if not existing_row:
                                cursor.execute("""
                                    INSERT INTO scan_executions (
                                        client_id, product_name, year, month, day, tool, status, evidence_path, log_output, duration_seconds, executed_at
                                    ) VALUES (?, ?, ?, ?, ?, ?, 'SUCCESS', ?, 'Scan importado do histórico de evidências.', 0, ?)
                                """, (client_id, prod_name, year, month, day, tool_name, ev_path, f"{year:04d}-{month:02d}-{day:02d} 12:00:00"))
                            elif existing_row["status"] != "SUCCESS" and ev_path:
                                cursor.execute("""
                                    UPDATE scan_executions
                                    SET status = 'SUCCESS', evidence_path = ?, log_output = 'Evidência gerada e validada com sucesso.'
                                    WHERE id = ?
                                """, (ev_path, existing_row["id"]))
                                
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    sync_existing_evidences()
    print("[✓] Banco de dados inicializado e sincronizado com as evidências do disco!")
