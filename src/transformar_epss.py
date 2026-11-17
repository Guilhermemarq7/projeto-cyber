import logging

from config import BRONZE_EPSS as BRONZE, PRATA, configurar_log

import pandas as pd

import limpeza
import utils

PADRAO = "epss_*.csv"
log = logging.getLogger(__name__)


def carregar():
    caminho = utils.mais_recente(BRONZE, PADRAO)
    df = pd.read_csv(caminho, comment="#")


    log.info(
        "EPSS carregado: arquivo=%s; linhas=%s; colunas=%s",
        caminho.name,
        len(df),
        len(df.columns),
    )

    log.debug(
        "Colunas do EPSS: %s",
        df.columns.tolist(),
    )

    log.info(
        "Valores ausentes por coluna no EPSS: %s",
        df.isna().sum().to_dict(),
    )


    return df, caminho



def converter_tipos(df):
    # Converte epss e percentile para numerico,
    # identifica falhas de conversao e remove essas linhas.
    novos_ausentes = {}
    falhas_conversao = pd.Series(False, index=df.index)

    for coluna in ["epss", "percentile"]:
        ausentes_antes = df[coluna].isna()

        df[coluna] = pd.to_numeric(
            df[coluna],
            errors="coerce",
        )

        falhas_coluna = (
            ~ausentes_antes
            & df[coluna].isna()
        )

        novos = int(falhas_coluna.sum())
        novos_ausentes[coluna] = novos
        falhas_conversao |= falhas_coluna

        log.info(
            "%s: novos ausentes apos conversao numerica: %s",
            coluna,
            novos,
        )

    removidas_conversao = int(falhas_conversao.sum())

    if removidas_conversao:
        log.warning(
            "Linhas removidas por falha de conversao numerica: %s",
            removidas_conversao,
        )

        log.warning(
            "Exemplos de CVEs com falha de conversao: %s",
            df.loc[
                falhas_conversao, "cve"
            ].head(5).tolist(),
        )

        df = df.loc[~falhas_conversao].copy()

    return df, novos_ausentes, removidas_conversao




def salvar(df):
    PRATA.mkdir(parents=True, exist_ok=True)

    destino = PRATA / "epss.parquet"
    df.to_parquet(destino, index=False)

    log.info(
        "EPSS salvo em: %s; linhas=%s; colunas=%s",
        destino,
        len(df),
        len(df.columns),
    )

    return destino



def main():
    df, origem = carregar()
    antes = len(df)

    df = limpeza.tirar_espacos(df)

    df, duplicadas = limpeza.conferir_chave(
        df,
        chave="cve",
    )

    df, novos_ausentes, removidas_conversao = converter_tipos(df)

    antes_faixa = len(df)

    df, epss_fora = limpeza.validar_faixa(
        df,
        "epss",
        0,
        1,
        remover=True,
    )

    df, percentile_fora = limpeza.validar_faixa(
        df,
        "percentile",
        0,
        1,
        remover=True,
    )

    removidas_faixa = antes_faixa - len(df)

    destino = salvar(df)

    utils.registrar(
        PRATA,
        origem,
        destino,
        antes,
        len(df),
        [
            "espacos removidos de colunas de texto antes da conferencia da chave",
            (
                f"chave 'cve' conferida: "
                f"{duplicadas} duplicata(s) encontrada(s) e removida(s)"
            ),
            (
                "epss e percentile convertidos para numerico; "
                f"falhas de conversao: epss={novos_ausentes['epss']}, "
                f"percentile={novos_ausentes['percentile']}; "
                f"linhas removidas por falha de conversao={removidas_conversao}"
            ),
            (
                "faixa oficial 0-1 validada e valores fora do dominio removidos: "
                f"epss={epss_fora}, percentile={percentile_fora}; "
                f"total de linhas removidas por faixa={removidas_faixa}"
            ),
            (
                "ausentes que ja existiam antes da conversao nao foram "
                "classificados como falha de conversao"
            ),
            (
                "valores altos validos de epss foram mantidos; "
                "nao sao tratados como erro estatistico"
            ),
            (
                "o arquivo representa um snapshot diario; "
                "a data do snapshot permanece no nome do arquivo de origem"
            ),
        ],
    )


if __name__ == "__main__":
    configurar_log()
    main()
