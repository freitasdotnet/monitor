# MONITOR.py — Monitor de Estabilidade de Internet

Monitor portátil de conectividade e utilitário de diagnóstico de rede escrito integralmente em Python puro. Não possui dependências externas — utiliza exclusivamente a biblioteca padrão do Python e comandos nativos do sistema operacional. Compatível com **Windows**, **Linux** e **macOS**.

---

## Sumário

- [Visão Geral](#visão-geral)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Argumentos da CLI](#argumentos-da-cli)
- [Arquitetura Interna](#arquitetura-interna)
- [Diagnósticos Realizados](#diagnósticos-realizados)
- [Detecção de Anomalias](#detecção-de-anomalias)
- [Score de Saúde](#score-de-saúde)
- [Dashboard em Tempo Real](#dashboard-em-tempo-real)
- [Relatório TXT](#relatório-txt)
- [Compatibilidade Cross-Platform](#compatibilidade-cross-platform)
- [Estrutura do Projeto](#estrutura-do-projeto)

---

## Visão Geral

O MONITOR executa ciclos de diagnóstico periódicos em paralelo, coletando métricas de latência, perda de pacotes, resolução DNS, alcançabilidade de gateway e estabilidade de rota. Todos os resultados são analisados em tempo real para detecção de anomalias e exibidos em um dashboard ANSI no terminal. Ao encerrar a sessão, um relatório `.txt` detalhado pode ser exportado.

O script foi projetado para ser **totalmente portável**: basta um arquivo `.py` e uma instalação padrão do Python 3.10+.

---

## Requisitos

- **Python 3.10 ou superior** (uso de `match/case` não está presente, mas `X | Y` em type hints e `slots=True` em dataclasses exigem 3.10+)
- **Sem dependências de terceiros** — apenas módulos da stdlib:
  - `argparse`, `concurrent.futures`, `dataclasses`, `datetime`, `ipaddress`
  - `json`, `pathlib`, `platform`, `re`, `shutil`, `socket`
  - `statistics`, `subprocess`, `sys`, `threading`, `time`

### Comandos nativos esperados no PATH

O script detecta automaticamente quais ferramentas estão disponíveis e adapta os comandos ao sistema operacional. Nenhuma delas precisa ser instalada manualmente em sistemas modernos.

| Finalidade | Windows | Linux | macOS |
|---|---|---|---|
| Ping | `ping` | `ping` | `ping` |
| Traceroute | `tracert`, `pathping` (fallback) | `traceroute`, `tracepath` (fallback) | `traceroute` |
| DNS diagnóstico | `nslookup` | `nslookup`, `dig` (fallback) | `nslookup`, `dig` (fallback) |
| Gateway / rotas | `ipconfig` | `ip route`, `route -n`, `netstat -rn` | `route -n get default`, `netstat -rn`, `ifconfig` |
| Configuração DNS | `ipconfig /all` | `/etc/resolv.conf` | `/etc/resolv.conf` |

---

## Instalação

Nenhuma instalação necessária. Basta clonar ou baixar o arquivo:

```bash
git clone https://github.com/seu-usuario/monitor-internet.git
cd monitor-internet
```

Ou apenas baixar o arquivo diretamente:

```bash
curl -O https://raw.githubusercontent.com/seu-usuario/monitor-internet/main/MONITOR.py
```

---

## Uso

```bash
python MONITOR.py
```

O monitoramento roda indefinidamente até ser interrompido com `Ctrl+C`. Ao encerrar, o script pergunta se o relatório TXT deve ser exportado.

### Exemplos práticos

```bash
# Monitoramento padrão com alvos e intervalo padrão
python MONITOR.py

# Monitorar um roteador local a cada 3 segundos
python MONITOR.py --target 192.168.1.1 --interval 3

# Monitorar múltiplos alvos com hosts DNS customizados
python MONITOR.py \
  --target 1.1.1.1 \
  --target 8.8.8.8 \
  --target meusite.com.br \
  --dns-host meusite.com.br \
  --dns-host github.com

# Sessão de 10 minutos com exportação automática de relatório
python MONITOR.py --duration 600 --auto-export --report-dir ./relatorios

# Execução em servidor sem terminal interativo (sem dashboard, sem cores)
python MONITOR.py --no-dashboard --no-color --auto-export

# Traceroute a cada ciclo com máximo de 30 hops
python MONITOR.py --traceroute-interval 1 --max-hops 30
```

---

## Argumentos da CLI

| Argumento | Tipo | Padrão | Descrição |
|---|---|---|---|
| `--target HOST` | `str` (repetível) | `1.1.1.1`, `8.8.8.8`, `google.com` | Alvo de ping. Pode ser IP ou hostname. Pode ser usado múltiplas vezes. |
| `--dns-host HOST` | `str` (repetível) | `google.com`, `cloudflare.com`, `openai.com` | Host a ser resolvido via DNS a cada ciclo. Pode ser usado múltiplas vezes. |
| `--interval SEGUNDOS` | `float` | `5.0` | Intervalo entre ciclos de monitoramento. Mínimo aplicado: `1.0`. |
| `--traceroute-interval N` | `int` | `6` | Executa traceroute a cada N ciclos. Mínimo: `1`. |
| `--max-hops N` | `int` | `20` | Número máximo de hops no traceroute. |
| `--duration SEGUNDOS` | `float` | `0.0` | Duração total da sessão. `0` = rodar até `Ctrl+C`. |
| `--report-dir CAMINHO` | `str` | `reports/` | Diretório de destino dos relatórios TXT. Criado automaticamente se não existir. |
| `--no-color` | flag | desativado | Desativa códigos ANSI de cor no terminal. Útil para CI/CD ou redirecionamento de saída. |
| `--no-dashboard` | flag | desativado | Desativa o refresh do dashboard. Apenas eventos e logs são impressos. |
| `--auto-export` | flag | desativado | Exporta o relatório automaticamente ao fim da sessão sem perguntar. Ativado implicitamente quando `--duration` é definido. |

---

## Arquitetura Interna

O projeto é organizado em classes com responsabilidades bem definidas. Não há uso de frameworks, ORM ou qualquer abstração externa.

```
MONITOR.py
│
├── MonitorConfig          # Dataclass com toda a configuração da sessão
├── SystemAdapter          # Abstração cross-platform de comandos nativos e informações de rede
│
├── PingDiagnostics        # Executa ping unitário e faz parse de latência e perda de pacotes
├── DNSDiagnostics         # Resolve hostnames com socket.getaddrinfo e mede tempo de resposta
├── TraceDiagnostics       # Executa traceroute e detecta mudanças de rota entre ciclos
│
├── SessionStats           # Armazena todos os resultados, calcula métricas e detecta anomalias
├── DiagnosticsEngine      # Orquestra os probes em paralelo via ThreadPoolExecutor por ciclo
│
├── Dashboard              # Renderiza o painel ANSI no terminal com refresh a cada ciclo
└── ReportWriter           # Gera o relatório TXT final consolidado
```

### Fluxo de execução por ciclo

```
main()
 └─ DiagnosticsEngine.run_cycle(N)
      ├─ [Thread] PingDiagnostics.probe(target) × len(targets)
      ├─ [Thread] DNSDiagnostics.resolve(host)  × len(dns_hosts)
      ├─ DiagnosticsEngine.check_gateway()
      └─ TraceDiagnostics.trace(target[0])      ← apenas no ciclo 1 e a cada N ciclos
           │
           ↓
      SessionStats.add_*()   ← análise de anomalias, eventos, atualização de métricas
           │
           ↓
      Dashboard.render()     ← refresh do terminal com os dados do ciclo
```

Todos os probes de ping e DNS de cada ciclo são disparados simultaneamente via `concurrent.futures.ThreadPoolExecutor` com até 8 workers. O traceroute é executado na thread principal após a conclusão dos outros probes para não competir com recursos de I/O.

### Modelos de dados

Todos os resultados são representados como `dataclass(slots=True)`, o que reduz o consumo de memória e impede a adição acidental de atributos:

| Dataclass | Descrição |
|---|---|
| `PingResult` | Resultado de um probe de ping: target, timestamp, sucesso, latência, perda, erro |
| `DNSResult` | Resultado de uma resolução DNS: host, tempo decorrido, endereços retornados |
| `GatewayResult` | Resultado do ping ao gateway padrão: IP, alcançabilidade, latência |
| `TraceHop` | Um hop de traceroute: número, host, latências individuais, timeout |
| `TraceResult` | Resultado completo de um traceroute: lista de hops, flag de mudança de rota |
| `CycleResult` | Agrega todos os resultados de um ciclo de diagnóstico |
| `AnomalyEvent` | Evento timestampado com severidade, categoria e mensagem |

---

## Diagnósticos Realizados

### Ping

- Comando construído dinamicamente por `SystemAdapter.ping_command()` para cada OS
- Executa um único probe por alvo (`-c 1` no Linux/macOS, `-n 1` no Windows)
- Parse de latência via regex: `(?:time[=<]\s*|tempo[=<]\s*)(\d+(?:[.,]\d+)?)\s*ms`
- Parse de perda de pacotes via regex: `(\d+(?:[.,]\d+)?)\s*%.*(?:loss|perda)`
- Tolerante a saídas em português (Windows PT-BR) e inglês

### DNS

- Resolução via `socket.getaddrinfo()` para medir tempo real de resolução do sistema
- Medição com `time.perf_counter()` para precisão em milissegundos
- Coleta de todos os IPs retornados (IPv4 e IPv6 dedupliacados)
- Execução de `nslookup`/`dig` nativo para inclusão no relatório final

### Gateway

- Descoberta automática via `SystemAdapter.default_gateway()` usando saída dos comandos de rota nativos
- Parse com múltiplos padrões regex para cobrir formatos de diferentes SO e versões
- Suporte a gateway em português (`Gateway Padrão`) e inglês (`Default Gateway`)
- Ping direto ao gateway a cada ciclo para verificar alcançabilidade local

### Traceroute

- Executado no ciclo 1 e depois a cada `traceroute_interval` ciclos
- Parse de hops com extração de IP e latências por linha de saída
- Detecção de mudança de rota comparando os primeiros 8 hops com o histórico dos últimos 20 traceroutes
- Contagem de hops com timeout (`*`) por execução
- Fallback automático: `tracert` → `pathping` (Windows), `traceroute` → `tracepath` (Linux)

### IP público

- Inferido via DNS usando o serviço `myip.opendns.com` no resolver `resolver1.opendns.com`
- Usa `nslookup` ou `dig` conforme disponibilidade
- Filtra IPs privados, loopback e reservados com `ipaddress.ip_address()`

---

## Detecção de Anomalias

Anomalias são registradas como `AnomalyEvent` com severidade `info`, `warning` ou `critical`. A detecção ocorre dentro de `SessionStats` a cada chamada `add_*()`:

| Categoria | Condição | Severidade |
|---|---|---|
| `connectivity` | Todos os targets falharam em um ciclo | `critical` |
| `connectivity` | Conectividade restaurada após interrupção | `info` |
| `latency` | Latência ≥ `high_latency_ms` (padrão: 180 ms) | `warning` |
| `latency` | Latência ≥ `severe_latency_ms` (padrão: 350 ms) | `critical` |
| `ping` | Target não respondeu | `warning` |
| `packet_loss` | Perda acumulada ≥ `packet_loss_warn_percent` (padrão: 5%) | `warning` |
| `packet_loss` | Perda acumulada ≥ `packet_loss_bad_percent` (padrão: 15%) | `critical` |
| `jitter` | Jitter ≥ `high_jitter_ms` (padrão: 60 ms) | `warning` |
| `degradation` | Média das últimas N amostras > 150% da média das N anteriores e delta > 40 ms | `warning` |
| `dns` | Falha de resolução DNS | `warning` |
| `dns` | Resolução DNS > 500 ms | `warning` |
| `gateway` | Gateway descoberto mas inalcançável | `warning` |
| `gateway` | Gateway não descoberto | `info` |
| `route` | Traceroute falhou | `warning` |
| `route` | Mudança de rota detectada | `warning` |
| `route` | ≥ 3 hops com timeout no traceroute | `warning` |

A detecção de **degradação de latência** usa uma janela deslizante configurável (`degradation_window`, padrão: 10 amostras). Compara a média das últimas `N` latências com a média das `N` anteriores. Dispara o evento se a média atual for mais de 1,5× a anterior **e** o delta absoluto for superior a 40 ms.

---

## Score de Saúde

O método `SessionStats.health_score()` retorna um inteiro de 0 a 100 calculado a partir de penalidades ponderadas:

```
score = 100

score -= min(45,  packet_loss_percent × 2.2)
score -= min(20,  interruptions × 8)
score -= min(15,  max(0, avg_latency_ms - 80) / 12)
score -= min(12,  max(0, jitter_ms - 25) / 5)
score -= min(10,  eventos_dns × 2)
score -= min(10,  eventos_route × 2)

score = clamp(score, 0, 100)
```

| Faixa | Rótulo |
|---|---|
| 85 – 100 | `Excellent` |
| 70 – 84 | `Good` |
| 50 – 69 | `Degraded` |
| 0 – 49 | `Unstable` |

---

## Dashboard em Tempo Real

O dashboard é renderizado via `sys.stdout.write()` com sequência de escape `\033[2J\033[H` para limpar o terminal a cada ciclo sem flickering. Seções exibidas:

- **Session Summary** — health score, uptime, latência avg/min/max, jitter, perda de pacotes, número de interrupções, tempo de execução
- **Current Cycle Step by Step** — status de cada etapa do ciclo atual (ping, DNS, gateway, traceroute)
- **Ping Monitoring** — tabela por target com status, latência e erro/perda
- **DNS Diagnostics** — tabela por host com tempo de resolução e endereços retornados
- **Gateway** — IP do gateway, status de alcançabilidade e latência
- **Traceroute / Route Stability** — último traceroute com hops, latência média por hop e flag de mudança de rota
- **Recent Alerts** — últimos 8 eventos com timestamp, severidade (colorida), categoria e mensagem

Cores são desativadas automaticamente se `--no-color` for passado ou podem ser removidas via `--no-dashboard` para execução em ambientes sem TTY.

---

## Relatório TXT

Gerado por `ReportWriter.write()` ao fim da sessão. Nome do arquivo: `monitor_YYYYMMDD_HHMMSS.txt`.

Estrutura do relatório:

```
INTERNET STABILITY MONITOR — SESSION REPORT
============================================================
Generated  : YYYY-MM-DD HH:MM:SS
OS         : Linux / Windows / macOS
Hostname   : <hostname>
Local IP   : <ip>
Public IP  : <ip>
Python     : 3.x.x

SESSION SUMMARY
------------------------------------------------------------------------
Start time / End time / Duration / Cycles / Interruptions / Health score
Average / Min / Max latency / Jitter

GATEWAY ANALYSIS
------------------------------------------------------------------------
IP do gateway, total de checks, checks bem-sucedidos, latência média

DNS CONFIGURATION
------------------------------------------------------------------------
Conteúdo de /etc/resolv.conf ou ipconfig /all

DNS DIAGNOSTICS
------------------------------------------------------------------------
Por host: total de resoluções, falhas, tempo médio

NATIVE DNS COMMAND OUTPUT
------------------------------------------------------------------------
Saída bruta de nslookup ou dig

LATENCY AND PACKET LOSS DETAILS
------------------------------------------------------------------------
Por target: total de probes, perda (%), latência avg/min/max

TRACEROUTE RESULTS
------------------------------------------------------------------------
Por execução: timestamp, target, hops com host e latência média

ANOMALY TIMELINE
------------------------------------------------------------------------
Lista cronológica de todos os AnomalyEvents com severidade e categoria

RAW METRIC SNAPSHOT
------------------------------------------------------------------------
JSON com snapshot final das métricas da sessão

DIAGNOSTIC CONCLUSIONS
------------------------------------------------------------------------
Conclusão textual baseada no health score e nos eventos registrados
```

---

## Compatibilidade Cross-Platform

| Funcionalidade | Windows | Linux | macOS |
|---|---|---|---|
| Ping | ✅ `ping -n 1 -w <ms>` | ✅ `ping -c 1 -W <s>` | ✅ `ping -c 1 -W <ms>` |
| Traceroute | ✅ `tracert -d -h` / `pathping` | ✅ `traceroute -n -m` / `tracepath` | ✅ `traceroute -n -m` |
| DNS nativo | ✅ `nslookup` | ✅ `nslookup` / `dig` | ✅ `nslookup` / `dig` |
| Descoberta de gateway | ✅ `ipconfig` | ✅ `ip route` / `route` / `netstat` | ✅ `route get default` / `netstat` |
| Configuração DNS | ✅ `ipconfig /all` | ✅ `/etc/resolv.conf` | ✅ `/etc/resolv.conf` |
| IP público | ✅ via `nslookup` | ✅ via `dig` / `nslookup` | ✅ via `dig` / `nslookup` |
| Dashboard ANSI | ⚠️ requer terminal com suporte ANSI | ✅ | ✅ |

> No Windows, o suporte a cores ANSI depende do terminal utilizado (Windows Terminal e PowerShell 7+ suportam nativamente). Em terminais sem suporte, use `--no-color`.

---

## Estrutura do Projeto

```
.
├── MONITOR.py       # Aplicação completa em arquivo único
└── reports/         # Criado automaticamente; armazena os relatórios TXT exportados
```

---

## Licença

MIT License — livre para usar, modificar e distribuir.
