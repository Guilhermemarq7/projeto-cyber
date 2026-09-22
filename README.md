# projeto-cyber

Pipeline de engenharia de dados (arquitetura medallion) sobre três fontes
públicas de dados de vulnerabilidades: NVD, EPSS e CISA KEV.

## Defeitos conhecidos das fontes

### NVD (National Vulnerability Database)

- `baseScore`, `baseSeverity` e `cvss_versao_usada` ficam ausentes em 2,0% dos CVEs de 2024 (791/39.233), 4,8% de 2025 (2.192/45.212) e 3,7% de 2026 (1.918/52.023) — os três sempre ausentes juntos, no mesmo CVE.
- Essa ausência parece coincidir com `vulnStatus = "Rejected"`: o próprio exemplo de CVE que inspecionamos manualmente (CVE-2024-0069) tem `vulnStatus: "Rejected"` e `metrics: {}` vazio — CVEs rejeitados nunca recebem pontuação CVSS. Vale confirmar isso com uma contagem exata antes da camada prata.
- `cvss_versao_usada` só assume 3 valores nos três anos (`cvssMetricV31`, `cvssMetricV40`, `cvssMetricV30`) — `cvssMetricV2` nunca é escolhido como métrica primária em 2024–2026, mesmo a auditoria de schema tendo encontrado 13.257 ocorrências brutas de `cvssMetricV2` no dataset completo: sempre existe uma versão mais prioritária disponível junto quando a v2 aparece.
- `num_referencias` e `num_fraquezas` são só contagens — a lista real de URLs de referência e de CWEs (`references`, `weaknesses`) não entra no relatório de perfilamento, só sua quantidade.
- `num_referencias` tem distribuição fortemente assimétrica em 2025 e 2026 (a maioria dos CVEs tem poucas referências, mas alguns têm até 93) — vale considerar isso ao decidir agregações na camada prata.
- `lastModified` tem uma fração muito pequena de valores repetidos (99,7%–100% de distintos, contra 100% de `id`/`published`) — alguns poucos CVEs compartilham exatamente o mesmo timestamp de última modificação.
- O perfilamento roda com `minimal=True` nos três arquivos por causa do volume — isso significa que a checagem de **linhas duplicadas não foi feita** para o NVD (diferente de EPSS e CISA KEV, que rodam no modo completo). Não há garantia hoje de que não existam CVEs duplicados dentro de um mesmo arquivo de ano.

### EPSS

- `percentile` é altamente correlacionado com `epss` e tem distribuição uniforme entre 0 e 1 — é matematicamente o rank/percentil do próprio score `epss`, ou seja, uma coluna redundante (equivalente ao caso `Total = Lead + Feature` do exemplo do Spotify).
- O arquivo bruto do EPSS vem com uma linha de metadado no topo (começando com `#`, ex.: versão do modelo/data de geração) — o `explorar.py` já trata isso com `pd.read_csv(..., comment="#")`; sem esse parâmetro a leitura quebraria.
- Fora isso, é a fonte mais "limpa" das três: 367.327 linhas, 0 valores ausentes, 0 linhas duplicadas, `cve` 100% único.

### CISA KEV

- `requiredAction` e `forensicTriage` são altamente correlacionados — o texto de `requiredAction` que cita "BOD 26-04"/"Forensics Triage Requirements" parece já indicar quando `forensicTriage` é `True`. Possivelmente redundante; vale confirmar antes de decidir manter as duas na prata.
- `forensicTriage` é extremamente desbalanceado: 97,5% `False` (1.651) contra 2,5% `True` (43).
- `requiredAction` também é desbalanceado: o texto mais comum ("Apply updates per vendor instructions.") aparece em 893 das 1.694 linhas (52,7%), contra outros 45 textos distintos.
- `cwes` tem 175 valores ausentes (10,3%) — nem todo CVE do catálogo tem CWE atribuído.
- `cwes` e `notes` não são campos atômicos: `cwes` empacota múltiplos códigos numa única célula separados por vírgula (ex.: `"CWE-78, CWE-184, CWE-287, CWE-918"`), e `notes` empacota múltiplas URLs separadas por `" ; "` — qualquer análise por CWE ou por link individual vai precisar desmembrar essas colunas na camada prata.
- `cveID` e `notes` são 100% únicos (1.694 valores distintos cada) — nenhum CVE duplicado no catálogo atual, e nenhuma nota repetida entre CVEs diferentes.
- Fora `cwes`, não há outros valores ausentes; 0 linhas duplicadas.