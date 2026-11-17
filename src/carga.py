"""Aulas 9/10: carrega a Prata; dbt constroi a Ouro."""

import logging

import duckdb

from config import OURO, PRATA, configurar_log

log = logging.getLogger(__name__)

BANCO = OURO / "projeto.duckdb"

# Uma linha na dimensao e na fato corresponde a uma CVE da NVD.
ARQUIVOS_PRATA = (
    "nvd",
    "epss",
    "cisa_kev",
    "vulnerabilidades_enriquecidas",
)


def um_valor(con, consulta):
    """Retorna o primeiro valor de uma consulta de verificacao."""
    return con.execute(consulta).fetchone()[0]


def criar_esquemas(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS prata")
    con.execute("CREATE SCHEMA IF NOT EXISTS ouro")


def carregar_prata(con):
    """Carrega os quatro Parquet existentes, sem novas transformacoes."""
    for nome in ARQUIVOS_PRATA:
        caminho = PRATA / f"{nome}.parquet"
        if not caminho.is_file():
            raise FileNotFoundError(f"Arquivo da Prata nao encontrado: {caminho}")

        con.execute(
            f"CREATE OR REPLACE TABLE prata.{nome} "
            "AS SELECT * FROM read_parquet(?)",
            [caminho.as_posix()],
        )
        quantidade = um_valor(con, f"SELECT COUNT(*) FROM prata.{nome}")
        log.info("Prata carregada: %s (%s linhas)", nome, quantidade)


def construir_ouro(con):
    """Separa descricoes (dimensao) de indicadores (fato), por CVE."""
    # A view antiga depende das tabelas que serao recriadas.
    con.execute("DROP VIEW IF EXISTS ouro.vw_vulnerabilidades_completas")

    con.execute("""
        CREATE OR REPLACE TABLE ouro.dim_cve AS
        SELECT
            id AS cve_id,
            sourceIdentifier AS fonte_publicadora,
            descricao_en AS descricao,
            vulnStatus AS status_nvd,
            published AS data_publicacao,
            lastModified AS data_ultima_modificacao,
            baseSeverity AS severidade_cvss,
            cvss_versao_usada AS versao_cvss,
            cvss_source AS fonte_cvss,
            cvss_type AS tipo_cvss,
            cvss_vector AS vetor_cvss,
            cwes
        FROM prata.vulnerabilidades_enriquecidas
    """)

    con.execute("""
        CREATE OR REPLACE TABLE ouro.fato_risco_cve AS
        SELECT
            id AS cve_id,
            baseScore AS pontuacao_cvss,
            cvss_num_metricas_na_versao AS qtd_metricas_cvss,
            cvss_selecao_ambigua AS selecao_cvss_ambigua,
            num_referencias AS qtd_referencias,
            num_fraquezas AS qtd_fraquezas,
            sem_pontuacao_cvss,
            vetor_ataque_rede,
            num_referencias_extremo AS referencias_extremas,
            epss AS probabilidade_epss,
            percentile AS percentil_epss,
            tem_epss,
            consta_kev,
            kev_dateAdded AS data_inclusao_kev,
            kev_knownRansomwareCampaignUse AS uso_ransomware_kev,
            cvss_alto_epss_top10
        FROM prata.vulnerabilidades_enriquecidas
    """)

    con.execute("""
        CREATE OR REPLACE VIEW ouro.vw_vulnerabilidades_completas AS
        SELECT
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
        FROM ouro.fato_risco_cve f
        JOIN ouro.dim_cve d USING (cve_id)
    """)

    log.info("Ouro criada: dim_cve, fato_risco_cve e view completa")


def conferir(con):
    """Confere grão, chaves, relacionamento e preservacao de indicadores."""
    origem = um_valor(con, "SELECT COUNT(*) FROM prata.vulnerabilidades_enriquecidas")
    dimensao = um_valor(con, "SELECT COUNT(*) FROM ouro.dim_cve")
    fato = um_valor(con, "SELECT COUNT(*) FROM ouro.fato_risco_cve")
    visao = um_valor(con, "SELECT COUNT(*) FROM ouro.vw_vulnerabilidades_completas")

    duplicadas_dim = um_valor(con, """
        SELECT COUNT(*) FROM (
            SELECT cve_id FROM ouro.dim_cve
            GROUP BY cve_id HAVING COUNT(*) > 1
        ) AS repetidas
    """)
    duplicadas_fato = um_valor(con, """
        SELECT COUNT(*) FROM (
            SELECT cve_id FROM ouro.fato_risco_cve
            GROUP BY cve_id HAVING COUNT(*) > 1
        ) AS repetidas
    """)
    chaves_vazias = um_valor(con, """
        SELECT
            (SELECT COUNT(*) FROM ouro.dim_cve
             WHERE cve_id IS NULL OR TRIM(cve_id) = '')
            +
            (SELECT COUNT(*) FROM ouro.fato_risco_cve
             WHERE cve_id IS NULL OR TRIM(cve_id) = '')
    """)
    orfaos = um_valor(con, """
        SELECT COUNT(*)
        FROM ouro.fato_risco_cve f
        LEFT JOIN ouro.dim_cve d USING (cve_id)
        WHERE d.cve_id IS NULL
    """)

    kev_origem = um_valor(con, """
        SELECT COUNT(*) FROM prata.vulnerabilidades_enriquecidas
        WHERE consta_kev IS TRUE
    """)
    kev_fato = um_valor(con, """
        SELECT COUNT(*) FROM ouro.fato_risco_cve WHERE consta_kev IS TRUE
    """)
    combinado_origem = um_valor(con, """
        SELECT COUNT(*) FROM prata.vulnerabilidades_enriquecidas
        WHERE cvss_alto_epss_top10 IS TRUE
    """)
    combinado_fato = um_valor(con, """
        SELECT COUNT(*) FROM ouro.fato_risco_cve
        WHERE cvss_alto_epss_top10 IS TRUE
    """)

    log.info(
        "Conferencia: origem=%s, dimensao=%s, fato=%s, view=%s",
        origem, dimensao, fato, visao,
    )
    log.info(
        "Chaves: duplicadas_dim=%s, duplicadas_fato=%s, vazias=%s, orfaos=%s",
        duplicadas_dim, duplicadas_fato, chaves_vazias, orfaos,
    )
    log.info(
        "Indicadores: KEV=%s (origem=%s), combinado=%s (origem=%s)",
        kev_fato, kev_origem, combinado_fato, combinado_origem,
    )

    if not (origem == dimensao == fato == visao):
        raise ValueError("A carga alterou a quantidade de CVEs")
    if duplicadas_dim or duplicadas_fato or chaves_vazias or orfaos:
        raise ValueError("Falha de integridade no grao ou nas chaves da Ouro")
    if kev_fato != kev_origem or combinado_fato != combinado_origem:
        raise ValueError("A carga alterou os indicadores de KEV ou CVSS/EPSS")

    log.info("Conferencias da camada Ouro aprovadas")


def preparar_modelagem():
    """Libera a view anterior para recriar as tabelas pelo dbt.

    A view depende da dimensao e da fato. Recriamos a view pelo dbt,
    depois das tabelas, sem deixar a conexao aberta.
    """
    con = duckdb.connect(str(BANCO))
    try:
        con.execute("DROP VIEW IF EXISTS ouro.vw_vulnerabilidades_completas")
    finally:
        con.close()


def validar_ouro():
    """Reabre o banco apos o dbt e verifica o modelo resultante."""
    con = duckdb.connect(str(BANCO), read_only=True)
    try:
        conferir(con)
    finally:
        con.close()


def main():
    OURO.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(BANCO))

    try:
        con.execute("BEGIN TRANSACTION")
        criar_esquemas(con)
        carregar_prata(con)
        # construir_ouro(con)  # Aula 10: agora executada pelo dbt.
        # conferir(con)       # Verificacao apos dbt, em validar_ouro().
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()

    log.info("Tabelas da Prata atualizadas no DuckDB: %s", BANCO)


if __name__ == "__main__":
    configurar_log()
    main()
