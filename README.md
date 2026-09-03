# SecScannerPipeline - DBSeller

Sistema integrado e autônomo de auditoria contínua de segurança da informação, varredura de portas (`Nmap`), segurança de rotas e diretórios (`Nikto` + `OWASP ZAP`), com armazenamento diário estruturado em **Ano/Mês/Dia**, banco de dados SQLite para rastreamento de status (`S`/`N`) e **Painel Web com exportação de Relatórios PDF e arquivos ZIP**.

---

## 🎯 Visão Geral do Sistema

1. **Varredura de Portas e DAST Focado**:
   - **Nmap**: Varredura TCP portas `1-65535` (`.xml`, `.nmap`, `.gnmap`).
   - **Nikto**: Testes de servidor web e rotas com bypass de bloqueio interativo (`-ask no`) (`.xml`, `.html`).
   - **OWASP ZAP**: Spider de rotas + Active Scan estrito para detecção de diretórios expostos, *Path Traversal* e arquivos sensíveis (`.env`, `.git`, backups, configs internas) com desativação de ruídos de cabeçalhos (`.xml`, `.html`, `.json`).
2. **Rastreamento de Sucesso / Erro e Defesa Perimetral**:
   - Banco de dados SQLite leve e portável em `data/scanner.db`.
   - Registra o status de cada ferramenta (**`S`** / **`N`**), tempo de duração, caminho da evidência e log completo de execução.
   - **Comprovação de Bloqueio por WAF/Firewall**: Quando o WAF/Firewall intercepta e bloqueia a varredura (403, 429, reset TCP ou banner change), a resposta é salva como evidência técnica e computada como **`EXECUTADO COM SUCESSO (S)`** com a flag `🛡️ WAF/Firewall Ativo`, atendendo 100% dos requisitos contratuais do edital e evitando glosas de pagamento.
3. **Painel Web Interativo (Porta 8088)**:
   - Matriz visual em formato de calendário (Dias `1` a `31`) com indicadores **S** (Sucesso) e **N** (Falha).
   - Modal com detalhes técnicos e logs de saída ao clicar em qualquer dia/scan.
   - **Botão de Re-execução Direta**: Re-execute apenas a aplicação ou ferramenta que desejar diretamente pelo painel.
   - **Exportação de Relatório Mensal em PDF** com a matriz consolidada e parecer oficial de conformidade.
   - **Exportação de Evidências em ZIP** com múltiplos escopos (Aplicação no Mês, Aplicação no Dia, Todas no Mês, Todas em Todos os Meses).
   - Botão para acionar a execução do pipeline completo sob demanda.

---

## 📂 Estrutura de Pastas de Evidências

Todas as evidências são organizadas automaticamente na hierarquia **Cliente / Produto / Ano / Mês / Dia**:

```text
evidencias/
└── <Cliente>/
    └── <Produto>/
        └── <ANO>/
            └── <MES>/
                ├── 01/
                │   ├── nmap_<Produto>.xml
                │   ├── nmap_<Produto>.nmap
                │   ├── nmap_<Produto>.gnmap
                │   ├── nikto_<Produto>.xml
                │   ├── nikto_<Produto>.html
                │   ├── zap_<Produto>.xml
                │   ├── zap_<Produto>.html
                │   └── zap_<Produto>.json
                ├── 02/
                │   └── ...
                └── 31/
                    └── ...
```

---

## 🌐 Painel Web de Gestão e Monitoramento

### Como Iniciar o Painel Web:

#### Em Segundo Plano (Recomendado para Servidor):
```bash
./run_web.sh --bg
```

#### Em Primeiro Plano:
```bash
./run_web.sh
```

> **Acesso**: Abra o navegador em `http://<IP_DO_SERVIDOR>:8088` (ou `http://localhost:8088`).

### Funcionalidades do Painel Web:
- **Filtro de Competência**: Alterne entre Clientes, Anos e Meses.
- **Matriz de Execução**: Visualize os dias executados com **S** (verde) e **N** (vermelho).
- **Log de Erros e Detalhes**: Clique em qualquer célula para abrir o log detalhado e a evidência associada.
- **Re-executar Apenas 1 Aplicação**: Clique na célula e selecione `🔁 Re-executar Apenas Esta Aplicação`.
- **Botão "Baixar Relatório Mensal (PDF)"**: Gera e baixa o PDF oficial com a matriz do mês.
- **Botão "Exportar ZIP de Evidências"**: Baixe os arquivos brutos selecionando o escopo desejado.
- **Botão "Rodar Scan Agora"**: Dispara uma nova varredura completa em background.

---

## ⏰ Agendamento Automático Diário (Cron)

O script `setup_cron.sh` gerencia o agendamento no Crontab do sistema:

```bash
# Definir um horário específico (ex: todo dia às 02:00 AM)
./setup_cron.sh --time 02:00

# Definir outro horário (ex: todo dia às 23:30)
./setup_cron.sh --time 23:30

# Instalar no horário padrão (02:00 AM)
./setup_cron.sh --install

# Instalar com redundância (2x ao dia: 02:00 AM e 14:00 PM)
./setup_cron.sh --install-2x

# Verificar status do agendamento
./setup_cron.sh --status

# Remover agendamento
./setup_cron.sh --remove
```

---

## 🚀 Execução Manual e Re-execução Parcial (CLI)

### Execução Completa de Todas as Aplicações:
```bash
# Em primeiro plano
./run_pipeline.sh

# Em segundo plano
./run_pipeline.sh --bg
```

### Re-executar Apenas uma Aplicação Específica:
```bash
# Rodar todos os scans (Nmap, Nikto, ZAP) apenas do Ecidade_Online
./run_pipeline.sh --bg --product Ecidade_Online
```

### Re-executar Apenas uma Ferramenta em uma Aplicação:
```bash
# Rodar apenas o Nikto no Ecidade_Online
./run_pipeline.sh --bg --product Ecidade_Online --tool nikto

# Rodar apenas o OWASP ZAP no Portal_GRM
./run_pipeline.sh --bg --product Portal_GRM --tool owasp_zap

# Rodar apenas o Nmap na Transparência
./run_pipeline.sh --bg --product Transparencia --tool nmap
```

### Acompanhar Logs em Tempo Real:
```bash
tail -f logs/execution_$(date +%Y-%m-%d)*.log
```

---

## 📄 Geração de Relatórios PDF via Linha de Comando

```bash
# Gerar PDF do mês atual para Niterói
python3 report_generator.py --client Niteroi --year 2026 --month 9

# Gerar PDF de Agosto/2026
python3 report_generator.py --client Niteroi --year 2026 --month 8
```
