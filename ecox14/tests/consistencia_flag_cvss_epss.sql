-- O teste passa quando nao retorna linhas.
-- Mantem NULL quando falta severidade CVSS ou percentil EPSS, como na Aula 7.
with verificacao as (
    select
        cve_id,
        severidade_cvss,
        percentil_epss,
        cvss_alto_epss_top10,
        case
            when severidade_cvss is null or percentil_epss is null
                then cast(null as boolean)
            else (
                severidade_cvss in ('HIGH', 'CRITICAL')
                and percentil_epss >= 0.90
            )
        end as valor_esperado
    from {{ ref('vw_vulnerabilidades_completas') }}
)
select
    cve_id,
    severidade_cvss,
    percentil_epss,
    cvss_alto_epss_top10,
    valor_esperado
from verificacao
where cvss_alto_epss_top10 is distinct from valor_esperado
