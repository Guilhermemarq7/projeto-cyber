# projeto-cyber

Pipeline de engenharia de dados sobre NVD, EPSS e CISA KEV, desenvolvido na disciplina Engenharia de Dados na Prática, da professora Bárbara Pimenta Caetano. Este repositório cobre as aulas 1 a 6, até Limpeza e Atributos Derivados (17/09/2026), usando a arquitetura medalhão.

O tema é o cruzamento de bases públicas de vulnerabilidades para analisar a relação entre gravidade técnica, probabilidade de exploração e exploração real. A pergunta norteadora apresentada na entrega do tema é:

> É possível antecipar quais vulnerabilidades têm maior chance de serem efetivamente exploradas (indicadas pelo CISA KEV) a partir da gravidade técnica (CVSS, no NVD) e da probabilidade de exploração estimada (EPSS)?

A Bronze e a Prata preparam os dados para essa análise. Ainda não há cruzamento entre as fontes, modelo preditivo ou resultado demonstrado sobre essa relação.

## Fontes de dados

As três fontes são públicas e abertas. O identificador CVE será a chave de ligação entre elas.

| Fonte e papel | Finalidade | Origem → Bronze | Chave |
|---|---|---|---|
| NVD — primária | Gravidade técnica e informações das CVEs | `.json.gz` → JSON descompactado | `id` |
| EPSS — secundária | Probabilidade estimada de exploração | `.csv.gz` → CSV descompactado | `cve` |
| CISA KEV — secundária | Vulnerabilidades com exploração conhecida | CSV → CSV | `cveID` |

- **NVD:** [catálogo de feeds](https://nvd.nist.gov/vuln/data-feeds); feeds de [2024](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.gz), [2025](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2025.json.gz) e [2026](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.json.gz). O recorte é pelo ano do identificador CVE, não necessariamente pelo ano de publicação, e não abrange toda a base histórica.
- **EPSS:** [CSV diário](https://epss.cyentia.com/epss_scores-current.csv.gz) e [documentação](https://www.first.org/epss).
- **CISA KEV:** [CSV](https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv) e [catálogo](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

CVSS, EPSS e presença no KEV representam conceitos distintos: gravidade técnica, probabilidade estimada e exploração conhecida, respectivamente.

## Arquitetura e execução

- `dados/bronze/`: arquivos por fonte (`nvd`, `epss`, `cisa_kev`), sem limpeza dos registros, e proveniência da ingestão.
- `dados/prata/`: resultados da limpeza, validações, conversão de tipos e atributos derivados em Parquet, com proveniência. A exploração da Bronze orienta esses tratamentos.
- `dados/ouro/`: reservado para uma etapa posterior; ainda não implementada.
- `src/`: scripts de ingestão, exploração e transformação. `limpeza.py` reúne funções genéricas de limpeza; `utils.py`, seleção de arquivos e registro de proveniência.
- `relatorios/`: HTMLs gerados pelo profiling. Dados e relatórios ficam fora do Git; os arquivos `proveniencia.jsonl` são versionados.

Execute os comandos **na raiz do repositório**. O ambiente foi instalado com Python 3.12; as dependências estão em [requirements.txt](requirements.txt): pandas, requests, fg-data-profiling, setuptools<82 e pyarrow.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

No PowerShell, a ativação é `.venv\Scripts\Activate.ps1`.

```bash
# Ingestão: requer acesso HTTPS às três fontes
python src/ingerir_nvd.py
python src/ingerir_epss.py
python src/ingerir_cisakev.py

# Exploração da Bronze: gera os cinco HTMLs em relatorios/
python src/explorar.py

# Transformações: geram os três Parquet em dados/prata/
python src/transformar_nvd.py
python src/transformar_epss.py
python src/transformar_cisakev.py
```

Exploração e transformação selecionam os arquivos mais recentes pelo nome datado, sendo um por ano no caso da NVD. É necessário ter os arquivos Bronze antes dessas etapas; o profiling completo pode ser demorado.

### Ingestão e proveniência

A ingestão descompacta NVD e EPSS, preservando o conteúdo dos registros. Os nomes incluem a data de extração `AAAAMMDD`, por exemplo `nvd_2024_20261001.json`. A identificação é diária: repetir a extração no mesmo dia pode substituir o arquivo anterior, decisão mantida para o escopo acadêmico. As transformações também substituem os respectivos Parquet; preserve cópias se precisar conservar resultados anteriores.

Cada execução acrescenta um registro JSONL:

- **Bronze:** `fonte`, `arquivo_bronze`, `extraido_em`, em `dados/bronze/<fonte>/proveniencia.jsonl`.
- **Prata:** `origem`, `arquivo_prata`, `linhas_antes`, `linhas_depois`, `decisoes`, `transformado_em`, em [dados/prata/proveniencia.jsonl](dados/prata/proveniencia.jsonl).

O código atual registra os horários de proveniência em UTC. O cabeçalho de metadados do EPSS permanece no CSV Bronze e é ignorado na leitura com `comment="#"`; não é convertido em colunas da Prata. Fonte, arquivo e horário já documentam a ingestão, sem necessidade de ampliar os metadados nesta etapa.

## Exploração automatizada — arquivos de 15/10/2026

Os resultados abaixo foram obtidos dos cinco relatórios HTML de profiling da NVD (2024, 2025 e 2026), EPSS e CISA KEV. Os relatórios foram gerados em **14/11/2026**, com data-profiling 4.20.0, a partir de arquivos identificados com a data de **15/10/2026**.

Os resultados representam a Bronze antes das transformações da Prata. Os relatórios HTML foram conferidos nesta auditoria, mas os arquivos brutos correspondentes não foram reprocessados.


| Fonte | Registros | Colunas | Células ausentes | Linhas duplicadas |
|---|---:|---:|---:|---:|
| NVD 2024 | 39.267 | 17 | 5.708 | 0 |
| NVD 2025 | 45.364 | 17 | 15.829 | 0 |
| NVD 2026 | 74.332 | 17 | 26.879 | 0 |
| EPSS | 389.824 | 3 | 0 | 0 |
| CISA KEV | 1.745 | 12 | 175 | 0 |

As chaves são únicas nos arquivos perfilados. Células ausentes não equivalem a linhas a remover.

### Achados relevantes

**NVD:** `baseScore` está ausente em 795, 2.197 e 3.538 registros de 2024, 2025 e 2026, respectivamente; os totais `Rejected` são 789, 1.787 e 1.007. Como as ausências superam as rejeições nos três anos, existem CVEs de outros status também sem pontuação. A sobreposição exata entre rejeição e ausência de CVSS não foi calculada. `baseScore` e `baseSeverity` têm forte associação, compatível com a classificação de severidade por faixas do score. `num_referencias` tem distribuição assimétrica, e extremos podem ser legítimos. As métricas selecionadas nos relatórios são das famílias v3.0, v3.1 e v4.0.

O profiling NVD extrai 17 campos do JSON aninhado. `num_referencias` conta entradas de `references`; `num_fraquezas` conta entradas de `weaknesses`, **não códigos CWE distintos**. A coluna `cwes` reúne valores das descrições em inglês, sem repetições, podendo incluir códigos ou marcadores de informação não especificada. A lista de URLs de referência não é extraída para o DataFrame.

**EPSS:** sem ausências ou duplicatas; `epss` varia de 0,00049 a 0,99999, e `percentile` fica em [0, 1]. A forte correlação é esperada: o percentil expressa posição relativa ao score. Ambos são mantidos por suas interpretações diferentes.

**CISA KEV:** as 175 ausências estão em `cwes` (10,0%). `forensicTriage` tem 1.661 valores `False` e 84 `True`; `knownRansomwareCampaignUse`, 1.384 `Unknown` e 361 `Known`. A associação entre `requiredAction` e `forensicTriage` não comprova que sejam intercambiáveis. `cwes` pode reunir vários códigos e `notes`, várias URLs na mesma célula; permanecem textuais nesta etapa. Correlações observadas não demonstram causalidade.

### Histórico preservado — 02/09/2026

O README anterior identificava uma extração de 02/09/2026: 39.233, 45.212 e 52.023 registros NVD (2024–2026), 367.327 EPSS e 1.694 KEV. As ausências de `baseScore` eram 791, 2.192 e 1.918, respectivamente. Já estavam registrados ausência de duplicatas, assimetria nas referências, associação score/severidade e EPSS/percentil, além de 175 ausências em `cwes` do KEV. Esses números preservam o histórico e não representam o profiling de outubro.

## Decisões de tratamento

As três transformações removem espaços nas bordas de nomes de colunas e textos e conferem a chave, mantendo a primeira ocorrência se houver repetição. Não há evidência nos resultados observados que justifique novas regras de conflitos, sinônimos ou normalização de identificadores CVE.

- **NVD:** concatena os três anos e verifica status inesperados. Remove CVEs `Rejected`, por serem registros rejeitados; converte `published` e `lastModified` para datas UTC e remove linhas com falhas de conversão de valores antes preenchidos. Remove `baseScore` fora de [0, 10], mas mantém ausências anteriores e CVEs válidas sem score, sinalizando-as sem imputação arbitrária.
- **EPSS:** converte `epss` e `percentile` para números e remove falhas de conversão de valores preenchidos ou valores fora de [0, 1]. Ausências anteriores não são classificadas como falhas de conversão. Scores altos dentro da faixa são mantidos, pois são informação relevante.
- **CISA KEV:** converte `dateAdded` e `dueDate` para datas, conta novos ausentes e verifica prazos anteriores à inclusão, sem remover automaticamente essas linhas. `dateAdded` indica inclusão no catálogo, não primeira exploração; `dueDate` é prazo de remediação. `Unknown` não vira `No`. Não há classificação de BOD por corte de data.

### Seleção CVSS e extremos

A política **local** de seleção CVSS considera métricas com `baseScore` preenchido e prefere v4.0, v3.1, v3.0 e v2, nessa ordem. Dentro da versão, prefere `Primary`, depois a fonte `nvd@nist.gov`; empates restantes são resolvidos deterministicamente. Essa não é uma precedência oficial da NVD e não invalida as outras métricas da origem.

São preservados `cvss_versao_usada`, `cvss_source`, `cvss_type`, `cvss_vector`, `cvss_num_metricas_na_versao` e `cvss_selecao_ambigua`. Scores de versões diferentes requerem controle da versão em futuras comparações.

Na comparação registrada em **30/09/2026**, o IQR sinalizou **5.411** registros, contra **1.653** pelo z-score: **3.758** somente pelo IQR e **0** somente pelo z-score. O IQR foi mantido por usar quartis, ser menos sensível a extremos e ser adequado à distribuição assimétrica de `num_referencias`. O código atual usa somente os limites `Q1 − 1,5 × IQR` e `Q3 + 1,5 × IQR`, sem remover os registros sinalizados. Extremo estatístico não é, por si só, erro de dado.

## Transformações da Prata — execução registrada em 01/10/2026

Os últimos registros de [proveniência da Prata](dados/prata/proveniencia.jsonl) são de **01/10/2026** (18:00:30–18:01:23 UTC). Usam `nvd_2024_20261001.json`, `nvd_2025_20261001.json`, `nvd_2026_20261001.json`, `epss_20261001.csv` e `cisa_kev_20261001.csv`. São resultados históricos confirmados no JSONL, distintos dos HTMLs de arquivos de 15/10; a transformação não foi reexecutada nesta revisão.

| Saída em `dados/prata/` | Linhas antes | Linhas depois | Removidas |
|---|---:|---:|---:|
| `nvd.parquet` | 150.967 | 147.445 | 3.522 |
| `epss.parquet` | 381.682 | 381.682 | 0 |
| `cisa_kev.parquet` | 1.730 | 1.730 | 0 |

- **NVD:** as 3.522 remoções foram de `Rejected`; zero duplicatas, falhas de conversão de datas ou scores fora da faixa. Foram mantidas 2.751 CVEs sem score; 5.420 extremos foram apenas sinalizados pelo IQR. Houve 110.429 flags de ataque Network e 2.751 vetores ausentes; 25.539 registros tinham múltiplas métricas válidas na versão selecionada e 1.302 exigiram desempate após as preferências.
- **EPSS:** zero duplicatas, falhas de conversão ou valores fora das faixas; nenhuma remoção.
- **CISA KEV:** zero duplicatas, novos ausentes na conversão de datas ou casos de `dueDate` anterior a `dateAdded`; nenhuma remoção.

## Atributos derivados e sinalizações

As funções ficam em [src/transformar_nvd.py](src/transformar_nvd.py).

| Atributo | Cálculo e finalidade |
|---|---|
| `sem_pontuacao_cvss` | `sinalizar_sem_cvss()` marca a ausência de `baseScore`, preservando e identificando CVEs sem pontuação. |
| `vetor_ataque_rede` | `derivar_vetor_ataque_rede()` retorna `True` quando encontra o componente `AV:N` no vetor selecionado, `False` quando o texto está presente sem esse componente e ausente quando `cvss_vector` é nulo. |
| `num_referencias_extremo` | `marcar_extremos_referencias()` sinaliza contagens fora dos limites de 1,5 × IQR; não remove linhas. |
| `cvss_selecao_ambigua` | `selecionar_metrica_cvss()` marca mais de uma candidata após as preferências, tornando o desempate identificável. |

`vetor_ataque_rede` é uma característica técnica complementar para futuras análises segmentadas da pergunta norteadora. Não repete o score CVSS nem mede probabilidade EPSS ou exploração conhecida pelo KEV. A função verifica o componente no texto presente, sem validar toda a sintaxe do vetor.

## Estado atual e próximas etapas

Ingestão, exploração e transformações individuais estão implementadas. Os registros de proveniência permitem acompanhar decisões e contagens; os Parquet podem ser reconstruídos a partir da Bronze correspondente. Downloads atuais podem ter conteúdo diferente dos snapshots históricos.

A integração por CVE, a análise conjunta e a camada Ouro ficam para as próximas etapas. Será necessário alinhar as datas dos snapshots e distinguir inclusão no KEV de data de exploração antes de avaliar a pergunta sobre antecipação.