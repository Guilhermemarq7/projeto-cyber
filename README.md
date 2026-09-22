# projeto-cyber

Pipeline de engenharia de dados (arquitetura medallion) sobre três fontes
públicas de dados de vulnerabilidades: NVD, EPSS e CISA KEV.

## Fontes de dados

| Fonte | Formato | Acesso | Extraído | Link |
|---|---|---|---|---|
| NVD (National Vulnerability Database) | JSON (`.json.gz` na origem) | aberto | 02/09/2026 | nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{ano}.json.gz |
| EPSS (Exploit Prediction Scoring System) | CSV (`.csv.gz` na origem) | aberto | 02/09/2026 | epss.cyentia.com/epss_scores-current.csv.gz |
| CISA KEV (Known Exploited Vulnerabilities) | CSV | aberto | 02/09/2026 | cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv |

**Chave de cada fonte** (para referência futura na modelagem da camada prata):
- NVD: `id` (identificador do CVE) — 100% único, confirmado pelo perfilamento.
- EPSS: `cve` — 100% único.
- CISA KEV: `cveID` — 100% único.

## Defeitos conhecidos das fontes

### NVD (National Vulnerability Database)

- `baseScore`, `baseSeverity` e `cvss_versao_usada` ficam ausentes em 2,0% dos CVEs de 2024 (791/39.233), 4,8% de 2025 (2.192/45.212) e 3,7% de 2026 (1.918/52.023) — os três sempre ausentes juntos, no mesmo CVE.
- Parte dessa ausência é explicada por `vulnStatus = "Rejected"`, confirmado com número exato: em 2024, 787 CVEs têm status Rejected e `num_referencias` zero — praticamente idêntico aos 791 CVEs sem `baseScore`. Em 2025, 1.783 Rejected batem exatamente com os 1.783 `num_referencias` zero, mas o total sem `baseScore` é maior (2.192). **Ou seja: `Rejected` explica a maior parte da ausência de CVSS, mas não toda — sobram CVEs de outros status também sem pontuação, ainda não identificados.**
- `baseScore` e `baseSeverity` são fortemente correlacionados (Phik entre 0,916 e 0,943 nos três anos) — esperado, já que `baseSeverity` é uma categoria (LOW/MEDIUM/HIGH/CRITICAL) derivada diretamente da faixa numérica de `baseScore`. Redundante por construção, como o caso `Total = Lead + Feature` do exemplo do Spotify.
- `num_fraquezas` (contagem de CWEs) é moderadamente correlacionado com `vulnStatus` (Phik 0,577 em 2024, caindo para 0,456 em 2026) — CVEs em status mais avançado de análise tendem a ter mais fraquezas catalogadas.
- `num_fraquezas` e `num_referencias` são só contagens — a lista real de CWEs e de URLs de referência não entra no dataframe perfilado, só a quantidade.
- `num_referencias` tem distribuição fortemente assimétrica em 2025 e 2026 (γ1 = 26,2 e 94,2 respectivamente) — a maioria dos CVEs tem poucas referências, mas alguns têm até 93.
- `cvss_versao_usada` só assume 3 valores nos três anos (`cvssMetricV31`, `cvssMetricV40`, `cvssMetricV30`) — `cvssMetricV2` nunca é escolhido como métrica primária em 2024–2026, mesmo a auditoria de schema tendo encontrado 13.257 ocorrências brutas de `cvssMetricV2` no dataset completo: sempre existe uma versão mais prioritária disponível junto quando a v2 aparece.
- 0 linhas duplicadas confirmadas nos três arquivos (checagem completa, sem `minimal=True`).

### EPSS

- `percentile` é altamente correlacionado com `epss` e tem distribuição uniforme entre 0 e 1 — é matematicamente o rank/percentil do próprio score `epss`, ou seja, uma coluna redundante.
- O arquivo bruto vem com uma linha de metadado no topo (começando com `#`) — o `explorar.py` já trata isso com `pd.read_csv(..., comment="#")`.
- 367.327 linhas, 0 valores ausentes, 0 linhas duplicadas, `cve` 100% único.

### CISA KEV

- `requiredAction` e `forensicTriage` são altamente correlacionados — o texto de `requiredAction` que cita "BOD 26-04"/"Forensics Triage Requirements" parece já indicar quando `forensicTriage` é `True`. Possivelmente redundante; ainda não confirmado.
- `forensicTriage` é extremamente desbalanceado: 97,5% `False` (1.651) contra 2,5% `True` (43).
- `requiredAction` é o texto mais comum ("Apply updates per vendor instructions.") em 893 das 1.694 linhas (52,7%), contra outros 45 textos distintos.
- `cwes` tem 175 valores ausentes (10,3%) — nem todo CVE do catálogo tem CWE atribuído.
- `cwes` e `notes` não são campos atômicos: `cwes` empacota múltiplos códigos numa célula separados por vírgula (ex.: `"CWE-78, CWE-184, CWE-287, CWE-918"`), e `notes` empacota múltiplas URLs separadas por `" ; "`.
- `cveID` e `notes` são 100% únicos (1.694 valores distintos cada). 0 linhas duplicadas, sem outros valores ausentes.