select
    id as cve_id,
    sourceIdentifier as fonte_publicadora,
    descricao_en as descricao,
    vulnStatus as status_nvd,
    published as data_publicacao,
    lastModified as data_ultima_modificacao,
    baseSeverity as severidade_cvss,
    cvss_versao_usada as versao_cvss,
    cvss_source as fonte_cvss,
    cvss_type as tipo_cvss,
    cvss_vector as vetor_cvss,
    cwes
from {{ source('prata', 'vulnerabilidades_enriquecidas') }}
