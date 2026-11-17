{{ config(materialized='view') }}

select
    f.*,
    d.fonte_publicadora,
    d.descricao,
    d.status_nvd,
    d.data_publicacao,
    d.data_ultima_modificacao,
    d.severidade_cvss,
    d.versao_cvss,
    d.fonte_cvss,
    d.tipo_cvss,
    d.vetor_cvss,
    d.cwes
from {{ ref('fato_risco_cve') }} f
join {{ ref('dim_cve') }} d using (cve_id)
