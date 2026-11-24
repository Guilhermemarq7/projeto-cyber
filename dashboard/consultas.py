"""Consultas de leitura do dashboard; nenhuma transformacao ocorre aqui."""

from pathlib import Path

import duckdb


RAIZ = Path(__file__).resolve().parent.parent
BANCO = RAIZ / "dados" / "ouro" / "projeto.duckdb"

# Os valores da interface sao passados como parametros, nunca inseridos no SQL.
# Percentil minimo None significa nao filtrar; nesse caso CVEs sem EPSS sao mantidas.
FILTROS_SQL = """
    where (? = 'Todas' or coalesce(severidade_cvss, 'Sem classificação') = ?)
      and (? is null or consta_kev = ?)
      and (? is null or percentil_epss >= ?)
"""


def _consultar(sql, parametros=None):
    """Executa uma consulta somente leitura e retorna um DataFrame."""
    if not BANCO.is_file():
        raise FileNotFoundError(f"Banco DuckDB nao encontrado: {BANCO}")

    con = duckdb.connect(str(BANCO), read_only=True)
    try:
        return con.execute(sql, parametros or []).df()
    finally:
        con.close()


def _parametros(severidade, consta_kev, percentil_minimo):
    return [
        severidade,
        severidade,
        consta_kev,
        consta_kev,
        percentil_minimo,
        percentil_minimo,
    ]


def severidades_disponiveis():
    """Retorna as classificacoes presentes no conjunto carregado."""
    dados = _consultar("""
        select distinct coalesce(severidade_cvss, 'Sem classificação') as severidade
        from ouro.vw_vulnerabilidades_completas
        order by severidade
    """)
    return ["Todas", *dados["severidade"].tolist()]


def resumo(severidade, consta_kev, percentil_minimo):
    """Calcula indicadores sobre o conjunto selecionado pelos filtros."""
    sql = """
        select
            count(*) as total_cves,
            count(*) filter (where consta_kev is true) as no_kev,
            count(*) filter (where cvss_alto_epss_top10 is true) as combinado,
            count(*) filter (where percentil_epss is null) as percentil_ausente
        from ouro.vw_vulnerabilidades_completas
    """ + FILTROS_SQL
    return _consultar(sql, _parametros(severidade, consta_kev, percentil_minimo)).iloc[0]


def distribuicao_severidade(severidade, consta_kev, percentil_minimo):
    """Quantidade de CVEs por classe de severidade na selecao atual."""
    sql = """
        select
            coalesce(severidade_cvss, 'Sem classificação') as severidade,
            count(*) as quantidade
        from ouro.vw_vulnerabilidades_completas
    """ + FILTROS_SQL + """
        group by 1
        order by quantidade desc, severidade
    """
    return _consultar(sql, _parametros(severidade, consta_kev, percentil_minimo))


def kev_por_faixa_epss(severidade, consta_kev, percentil_minimo):
    """Compara a proporcao de CVEs no KEV dentro de cada faixa EPSS."""
    sql = """
        with filtradas as (
            select percentil_epss, consta_kev
            from ouro.vw_vulnerabilidades_completas
    """ + FILTROS_SQL + """
        ), faixas as (
            select
                case
                    when percentil_epss is null then 5
                    when percentil_epss < 0.50 then 1
                    when percentil_epss < 0.75 then 2
                    when percentil_epss < 0.90 then 3
                    else 4
                end as ordem,
                case
                    when percentil_epss is null then 'Sem percentil'
                    when percentil_epss < 0.50 then 'Abaixo de 50%'
                    when percentil_epss < 0.75 then '50% a menos de 75%'
                    when percentil_epss < 0.90 then '75% a menos de 90%'
                    else '90% a 100%'
                end as faixa,
                consta_kev
            from filtradas
        )
        select
            faixa,
            count(*) as total_cves,
            count(*) filter (where consta_kev is true) as no_kev,
            round(
                100.0 * count(*) filter (where consta_kev is true) / nullif(count(*), 0),
                2
            ) as percentual_kev
        from faixas
        group by ordem, faixa
        order by ordem
    """
    return _consultar(sql, _parametros(severidade, consta_kev, percentil_minimo))


def vulnerabilidades(severidade, consta_kev, percentil_minimo, limite=50):
    """Detalhamento paginado por limite, sem carregar toda a base para a tela."""
    sql = """
        select
            cve_id,
            severidade_cvss,
            pontuacao_cvss,
            probabilidade_epss,
            percentil_epss,
            consta_kev,
            cvss_alto_epss_top10
        from ouro.vw_vulnerabilidades_completas
    """ + FILTROS_SQL + """
        order by consta_kev desc, percentil_epss desc nulls last,
                 pontuacao_cvss desc nulls last, cve_id
        limit ?
    """
    parametros = _parametros(severidade, consta_kev, percentil_minimo)
    return _consultar(sql, [*parametros, int(limite)])
