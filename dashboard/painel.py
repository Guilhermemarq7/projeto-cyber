"""Dashboard de consulta da camada Ouro. Nenhum SQL nem carga aqui."""

from datetime import datetime

import streamlit as st

import consultas


st.set_page_config(page_title="Projeto Cyber | Vulnerabilidades", page_icon="🛡️", layout="wide")
st.title("Projeto Cyber — Painel de Vulnerabilidades")
st.caption(
    "Dados da camada Ouro · Fontes: NVD, EPSS e CISA KEV · "
    "Análise exploratória, não previsão de exploração."
)

if not consultas.BANCO.is_file():
    st.error("Banco local ainda não encontrado. Execute o pipeline antes de abrir o painel.")
    st.code("python src/pipeline.py", language="bash")
    st.stop()

try:
    with st.sidebar:
        st.header("Filtros")
        severidade = st.selectbox("Severidade CVSS", consultas.severidades_disponiveis())
        opcao_kev = st.selectbox(
            "Presença no CISA KEV",
            ["Todas", "Consta no KEV", "Não consta no KEV"],
        )
        consta_kev = {
            "Todas": None,
            "Consta no KEV": True,
            "Não consta no KEV": False,
        }[opcao_kev]
        opcao_percentil = st.selectbox(
            "Percentil EPSS mínimo",
            ["Sem filtro", "0,50", "0,75", "0,90", "0,95"],
        )
        percentil_minimo = {
            "Sem filtro": None,
            "0,50": 0.50,
            "0,75": 0.75,
            "0,90": 0.90,
            "0,95": 0.95,
        }[opcao_percentil]
        limite = st.selectbox("Linhas na tabela detalhada", [20, 50, 100], index=1)

    resumo = consultas.resumo(severidade, consta_kev, percentil_minimo)
    severidades = consultas.distribuicao_severidade(severidade, consta_kev, percentil_minimo)
    faixas = consultas.kev_por_faixa_epss(severidade, consta_kev, percentil_minimo)
    detalhes = consultas.vulnerabilidades(severidade, consta_kev, percentil_minimo, limite)

    def formatar_numero(valor):
        return f"{int(valor):,}".replace(",", ".")

    col1, col2, col3 = st.columns(3)
    col1.metric("CVEs na selecao", formatar_numero(resumo["total_cves"]))
    col2.metric("Constam no KEV", formatar_numero(resumo["no_kev"]))
    col3.metric("CVSS alto + EPSS top 10%", formatar_numero(resumo["combinado"]))

    esquerda, direita = st.columns([3, 2])
    with esquerda:
        st.subheader("Quantidade por severidade CVSS")
        if severidades.empty:
            st.info("Nenhum registro atende aos filtros.")
        else:
            st.bar_chart(severidades, x="severidade", y="quantidade")

    with direita:
        st.subheader("Presença no KEV por faixa EPSS")
        if faixas.empty:
            st.info("Não há dados para as faixas selecionadas.")
        else:
            st.bar_chart(faixas, x="faixa", y="percentual_kev")
            st.caption("Percentual de CVEs catalogadas no KEV em cada faixa; não é previsão.")
            st.dataframe(faixas, hide_index=True, use_container_width=True)

    st.subheader("Vulnerabilidades detalhadas")
    st.dataframe(detalhes, hide_index=True, use_container_width=True)
    st.caption(
        f"Exibindo até {limite} linhas de {formatar_numero(resumo['total_cves'])} "
        "CVEs filtradas. Ausência no KEV significa apenas não catalogada "
        "no snapshot consultado."
    )
    atualizacao_banco = datetime.fromtimestamp(consultas.BANCO.stat().st_mtime)
    st.caption(
        "Fontes: NVD, EPSS e CISA KEV | Consulta: "
        "ouro.vw_vulnerabilidades_completas | "
        f"Arquivo DuckDB modificado em {atualizacao_banco:%d/%m/%Y %H:%M} "
        "(não é a data de referência dos snapshots)."
    )
except Exception as erro:
    st.error("Não foi possível consultar a camada Ouro. Confira o banco e o pipeline.")
    st.exception(erro)
    st.stop()
