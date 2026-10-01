from pathlib import Path

import pandas as pd

import limpeza
import utils

BRONZE = Path("dados/bronze/epss")
PRATA = Path("dados/prata")
PADRAO = "epss_*.csv"


def carregar():
    caminho = utils.mais_recente(BRONZE, PADRAO)
    df = pd.read_csv(caminho, comment="#")

    print("lido:", caminho.name, df.shape)
    print(df.columns.tolist())
    print(df.isna().sum())

    return df, caminho


def converter_tipos(df):
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

        print(
            f"{coluna}: novos ausentes apos conversao numerica:",
            novos,
        )

    removidas_conversao = int(falhas_conversao.sum())

    if removidas_conversao:
        print(
            "linhas removidas por falha de conversao numerica:",
            removidas_conversao,
        )
        print(df.loc[falhas_conversao])
        df = df.loc[~falhas_conversao].copy()

    return df, novos_ausentes, removidas_conversao


def salvar(df):
    PRATA.mkdir(parents=True, exist_ok=True)

    destino = PRATA / "epss.parquet"
    df.to_parquet(destino, index=False)

    print("salvo em:", destino, df.shape)

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
    main()
