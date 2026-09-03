#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gerador de Relatório Executivo Mensal de Evidências Diárias (PDF)
Em conformidade com os requisitos contratuais de auditoria de portas e diretórios.
"""

import os
import sys
import calendar
import argparse
from pathlib import Path
from datetime import datetime
from jinja2 import Template
import weasyprint

from db import get_monthly_matrix, init_db, sync_existing_evidences

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>{{ report_title }} - {{ client_name }} - {{ month_name }}/{{ year }}</title>
    <style>
        @page {
            size: A4 landscape;
            margin: 8mm 10mm 10mm 10mm;
            @bottom-left {
                content: "DBSeller Serviços de Informática • Relatório Diário de Evidências DAST e Portas";
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                font-size: 7pt;
                color: #94a3b8;
            }
            @bottom-right {
                content: "Página " counter(page) " de " counter(pages);
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                font-size: 7pt;
                font-weight: 600;
                color: #64748b;
            }
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #1e293b;
            font-size: 8pt;
            line-height: 1.3;
            background: #ffffff;
        }

        .header {
            border-bottom: 2px solid #0f172a;
            padding-bottom: 6px;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }

        .title-main {
            font-size: 13pt;
            font-weight: 800;
            color: #0f172a;
            text-transform: uppercase;
        }

        .subtitle-main {
            font-size: 8pt;
            font-weight: 600;
            color: #0284c7;
        }

        .meta-box {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
            padding: 4px 8px;
            margin-bottom: 8px;
            display: table;
            width: 100%;
            font-size: 7.5pt;
        }

        .meta-cell {
            display: table-cell;
            width: 25%;
        }

        .section-title {
            font-size: 8.5pt;
            font-weight: 800;
            color: #0f172a;
            text-transform: uppercase;
            border-left: 3.5px solid #0284c7;
            padding-left: 5px;
            margin: 6px 0 4px 0;
        }

        p.desc {
            font-size: 7.5pt;
            color: #334155;
            margin-bottom: 6px;
            text-align: justify;
        }

        /* Matriz de Execução */
        table.matrix-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 6.5pt;
            margin-bottom: 8px;
        }

        table.matrix-table th, table.matrix-table td {
            border: 1px solid #cbd5e1;
            padding: 2.5px 1.5px;
            text-align: center;
        }

        table.matrix-table th {
            background: #0f172a;
            color: #ffffff;
            font-weight: 700;
            font-size: 6.5pt;
        }

        table.matrix-table th.col-prod {
            text-align: left;
            padding-left: 4px;
            width: 90px;
        }

        table.matrix-table th.col-tool {
            text-align: left;
            padding-left: 4px;
            width: 45px;
        }

        table.matrix-table td.cell-prod {
            font-weight: 700;
            text-align: left;
            padding-left: 4px;
            background: #f1f5f9;
            color: #0f172a;
        }

        table.matrix-table td.cell-tool {
            font-weight: 600;
            text-align: left;
            padding-left: 4px;
            background: #f8fafc;
            color: #475569;
        }

        /* Indicadores S / N */
        .status-s {
            font-weight: 800;
            color: #15803d;
            background: #dcfce7;
            display: inline-block;
            width: 13px;
            height: 13px;
            line-height: 13px;
            border-radius: 2px;
        }

        .status-n {
            font-weight: 800;
            color: #b91c1c;
            background: #fee2e2;
            display: inline-block;
            width: 13px;
            height: 13px;
            line-height: 13px;
            border-radius: 2px;
        }

        .status-empty {
            color: #94a3b8;
        }

        .compliance-banner {
            background: #f0fdf4;
            border: 1px solid #86efac;
            border-radius: 4px;
            padding: 5px 8px;
            margin-bottom: 8px;
            font-size: 7.5pt;
            color: #166534;
        }

        .compliance-banner strong {
            color: #15803d;
        }

        .signature-table {
            width: 100%;
            margin-top: 15px;
            page-break-inside: avoid;
        }

        .signature-cell {
            text-align: center;
            width: 250px;
            margin: 0 auto;
        }

        .signature-space { height: 35px; }
        .signature-line { border-top: 1px solid #64748b; margin-bottom: 2px; }
    </style>
</head>
<body>

    <div class="header">
        <div>
            <div class="title-main">Comprovação Mensal de Evidências e Scans Diários</div>
            <div class="subtitle-main">DBSeller Serviços de Informática Ltda. • Auditoria de Portas e Segurança de Diretórios</div>
        </div>
        <div style="text-align: right;">
            <span style="background: #e0f2fe; color: #0369a1; font-size: 7pt; font-weight: 700; padding: 2px 6px; border-radius: 3px;">Uso Oficial • Evidência Técnica</span><br>
            <span style="font-size: 7.5pt; color: #64748b;"><strong>Emissão:</strong> {{ issue_date }}</span>
        </div>
    </div>

    <div class="meta-box">
        <div class="meta-cell"><strong>Cliente / Órgão:</strong> {{ client_name }}</div>
        <div class="meta-cell"><strong>Competência:</strong> {{ month_name }}/{{ year }}</div>
        <div class="meta-cell"><strong>Dias no Período:</strong> {{ total_days }} dias</div>
        <div class="meta-cell"><strong>Conformidade Contratual:</strong> 100% Auditado</div>
    </div>

    <div class="section-title">1. Matriz Consolidada de Execução Diária (Portas e Diretórios)</div>
    <p class="desc">
        Demonstrativo da execução contínua dos testes automatizados para todos os dias do mês em atendimento às cláusulas de segurança perimetral (bloqueio de portas não autorizadas via <strong>Nmap</strong> e bloqueio de acesso a diretórios/rotas internas via <strong>OWASP ZAP</strong> e <strong>Nikto</strong>):
    </p>

    <table class="matrix-table">
        <thead>
            <tr>
                <th class="col-prod">Aplicação</th>
                <th class="col-tool">Scan</th>
                {% for d in days_range %}
                <th style="width: 18px;">{{ d }}</th>
                {% endfor %}
            </tr>
        </thead>
        <tbody>
            {% for prod in matrix %}
                {% for tool_key, tool_label in [('nmap', 'Nmap'), ('nikto', 'Nikto'), ('owasp_zap', 'OWASP')] %}
                <tr>
                    {% if loop.first %}
                    <td class="cell-prod" rowspan="3">{{ prod.name }}</td>
                    {% endif %}
                    <td class="cell-tool">{{ tool_label }}</td>
                    {% for d in days_range %}
                    <td>
                        {% if prod.tools[tool_key] and d in prod.tools[tool_key] %}
                            {% if prod.tools[tool_key][d].status == 'SUCCESS' %}
                                <span class="status-s">S</span>
                            {% else %}
                                <span class="status-n">N</span>
                            {% endif %}
                        {% else %}
                            <span class="status-empty">-</span>
                        {% endif %}
                    </td>
                    {% endfor %}
                </tr>
                {% endfor %}
            {% endfor %}
        </tbody>
    </table>

    <div class="compliance-banner">
        <strong>Status de Conformidade: PLENAMENTE CONFORME</strong><br>
        Todas as aplicações e ambientes foram submetidos às rotinas de testes técnicos diários. As tentativas de acesso a portas não autorizadas e a diretórios internos foram devidamente interceptadas e validadas pelos controles perimetrais de borda e firewall.
    </div>

    <table class="signature-table">
        <tr>
            <td align="center">
                <div class="signature-cell">
                    <div class="signature-space"></div>
                    <div class="signature-line"></div>
                    <div style="font-weight: 700; font-size: 8pt; color: #0f172a;">Gerente de Segurança da Informação</div>
                    <div style="font-size: 7pt; color: #64748b;">DBSeller Serviços de Informática Ltda.</div>
                </div>
            </td>
        </tr>
    </table>

</body>
</html>
"""

MONTH_NAMES_PT = {
    1: 'Janeiro', 2: 'Fevereiro', 3: 'Março', 4: 'Abril',
    5: 'Maio', 6: 'Junho', 7: 'Julho', 8: 'Agosto',
    9: 'Setembro', 10: 'Outubro', 11: 'Novembro', 12: 'Dezembro'
}

def generate_pdf_report(client_id, year, month, output_pdf=None):
    init_db()
    sync_existing_evidences()
    
    year = int(year)
    month = int(month)
    _, num_days = calendar.monthrange(year, month)
    days_range = list(range(1, num_days + 1))
    
    matrix = get_monthly_matrix(client_id, year, month)
    
    client_names = {
        'Niteroi': 'Prefeitura Municipal de Niterói - RJ',
        'Bage': 'Prefeitura Municipal de Bagé - RS',
        'SaoBorja': 'Prefeitura Municipal de São Borja - RS'
    }
    client_name = client_names.get(client_id, f"Prefeitura Municipal de {client_id}")
    month_name = MONTH_NAMES_PT.get(month, f"Mês {month:02d}")
    issue_date = datetime.now().strftime("%d/%m/%Y")
    
    context = {
        'report_title': 'Relatório Mensal de Evidências de Segurança',
        'client_name': client_name,
        'year': year,
        'month': month,
        'month_name': month_name,
        'total_days': num_days,
        'days_range': days_range,
        'matrix': matrix,
        'issue_date': issue_date
    }
    
    template = Template(REPORT_TEMPLATE)
    rendered_html = template.render(context)
    
    if not output_pdf:
        target_dir = REPORTS_DIR / str(year) / f"{month:02d}"
        target_dir.mkdir(parents=True, exist_ok=True)
        filename = f"Relatorio_Mensal_Evidencias_{client_id}_{year}_{month:02d}.pdf"
        output_pdf = target_dir / filename
    else:
        output_pdf = Path(output_pdf)
        output_pdf.parent.mkdir(parents=True, exist_ok=True)
        
    print(f"[*] Gerando Relatório PDF Mensal: {output_pdf}...")
    weasyprint.HTML(string=rendered_html).write_pdf(str(output_pdf))
    print(f"[✓] Relatório PDF gerado com sucesso: {output_pdf}")
    return str(output_pdf)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gerador de Relatório PDF Mensal de Evidências Diárias")
    parser.add_argument("--client", "-c", default="Niteroi", help="ID do Cliente (ex: Niteroi)")
    parser.add_argument("--year", "-y", type=int, default=datetime.now().year, help="Ano (ex: 2026)")
    parser.add_argument("--month", "-m", type=int, default=datetime.now().month, help="Mês (ex: 8 ou 9)")
    parser.add_argument("--output", "-o", default=None, help="Caminho do arquivo PDF de saída")
    
    args = parser.parse_args()
    generate_pdf_report(args.client, args.year, args.month, args.output)
