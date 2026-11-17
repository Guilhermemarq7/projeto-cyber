select
    id as cve_id,
    baseScore as pontuacao_cvss,
    cvss_num_metricas_na_versao as qtd_metricas_cvss,
    cvss_selecao_ambigua as selecao_cvss_ambigua,
    num_referencias as qtd_referencias,
    num_fraquezas as qtd_fraquezas,
    sem_pontuacao_cvss,
    vetor_ataque_rede,
    num_referencias_extremo as referencias_extremas,
    epss as probabilidade_epss,
    percentile as percentil_epss,
    tem_epss,
    consta_kev,
    kev_dateAdded as data_inclusao_kev,
    kev_knownRansomwareCampaignUse as uso_ransomware_kev,
    cvss_alto_epss_top10
from {{ source('prata', 'vulnerabilidades_enriquecidas') }}
