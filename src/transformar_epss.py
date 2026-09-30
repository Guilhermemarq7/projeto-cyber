from pathlib import Path

import pandas as pd

import utils
import limpeza

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
    """Converte epss/percentile e mede se o coerce criou novos ausentes."""
    novos_ausentes = {}

    for coluna in ["epss", "percentile"]:
        antes = int(df[coluna].isna().sum())
        df[coluna] = pd.to_numeric(df[coluna], errors="coerce")
        depois = int(df[coluna].isna().sum())
        novos = max(0, depois - antes)
        novos_ausentes[coluna] = novos
        print(f"{coluna}: novos ausentes apos conversao numerica:", novos)

    return df, novos_ausentes


def salvar(df):
    PRATA.mkdir(parents=True, exist_ok=True)
    destino = PRATA / "epss.parquet"
    df.to_parquet(destino, index=False)
    print("salvo em:", destino, df.shape)
    return destino


def main():
    df, origem = carregar()
    antes = len(df)

    # Primeiro normaliza texto; depois confere a chave ja normalizada.
    df = limpeza.tirar_espacos(df)
    duplicadas = int(df["cve"].duplicated().sum())
    df = limpeza.conferir_chave(df, chave="cve")

    df, novos_ausentes = converter_tipos(df)

    # FIRST define epss e percentile no intervalo 0-1.
    epss_fora = int((df["epss"].notna() & ~df["epss"].between(0, 1)).sum())
    percentile_fora = int(
        (df["percentile"].notna() & ~df["percentile"].between(0, 1)).sum()
    )
    limpeza.validar_faixa(df, "epss", 0, 1)
    limpeza.validar_faixa(df, "percentile", 0, 1)

    destino = salvar(df)
    utils.registrar(PRATA, origem, destino, antes, len(df), [
        "espacos removidos de colunas de texto antes da conferencia da chave",
        f"chave 'cve' conferida: {duplicadas} duplicata(s) encontrada(s) e removida(s)",
        (
            "epss e percentile convertidos/confirmados como numericos; "
            f"novos ausentes criados pela conversao: epss={novos_ausentes['epss']}, "
            f"percentile={novos_ausentes['percentile']}"
        ),
        (
            "faixa oficial 0-1 validada: "
            f"epss fora da faixa={epss_fora}, percentile fora da faixa={percentile_fora}"
        ),
        "nenhum valor alto de epss foi removido como extremo: score alto e informacao relevante, nao erro estatistico",
        "o arquivo representa um snapshot diario; a data do snapshot permanece registrada no nome do arquivo de origem",
    ])


if __name__ == "__main__":
    main()
