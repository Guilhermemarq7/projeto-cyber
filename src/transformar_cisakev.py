from pathlib import Path

import pandas as pd

import limpeza
import utils

BRONZE = Path("dados/bronze/cisa_kev")
PRATA = Path("dados/prata")
PADRAO = "cisa_kev_*.csv"


def carregar():
    caminho = utils.mais_recente(BRONZE, PADRAO)
    df = pd.read_csv(caminho)
    print("lido:", caminho.name, df.shape)
    print(df.columns.tolist())
    print(df.isna().sum())
    return df, caminho


def converter_tipos(df):
    """Converte as datas e mede se o coerce criou novos ausentes."""
    novos_ausentes = {}

    for coluna in ["dateAdded", "dueDate"]:
        antes = int(df[coluna].isna().sum())
        df[coluna] = pd.to_datetime(
            df[coluna], format="%Y-%m-%d", errors="coerce"
        )
        depois = int(df[coluna].isna().sum())
        novos = max(0, depois - antes)
        novos_ausentes[coluna] = novos
        print(f"{coluna}: novos ausentes apos conversao de data:", novos)

    return df, novos_ausentes


def salvar(df):
    PRATA.mkdir(parents=True, exist_ok=True)
    destino = PRATA / "cisa_kev.parquet"
    df.to_parquet(destino, index=False)
    print("salvo em:", destino, df.shape)
    return destino


def main():
    df, origem = carregar()
    antes = len(df)

    # Primeiro normaliza texto; depois confere a chave ja normalizada.
    df = limpeza.tirar_espacos(df)
    duplicadas = int(df["cveID"].duplicated().sum())
    df = limpeza.conferir_chave(df, chave="cveID")

    df, novos_ausentes = converter_tipos(df)

    ambas_preenchidas = df["dateAdded"].notna() & df["dueDate"].notna()
    datas_invertidas = int(
        (ambas_preenchidas & (df["dueDate"] < df["dateAdded"])).sum()
    )
    limpeza.validar_ordem_datas(df, "dateAdded", "dueDate")

    destino = salvar(df)
    utils.registrar(PRATA, origem, destino, antes, len(df), [
        "espacos removidos de colunas de texto antes da conferencia da chave",
        f"chave 'cveID' conferida: {duplicadas} duplicata(s) encontrada(s) e removida(s)",
        (
            "dateAdded e dueDate convertidos para datetime; "
            f"novos ausentes criados pela conversao: dateAdded={novos_ausentes['dateAdded']}, "
            f"dueDate={novos_ausentes['dueDate']}"
        ),
        f"ordem temporal conferida: {datas_invertidas} caso(s) com dueDate anterior a dateAdded",
        "dateAdded mantida como data de inclusao no catalogo, nao como data da primeira exploracao",
        "dueDate mantida como prazo de remediacao publicado pela CISA, nao como atributo tecnico da vulnerabilidade",
        "regra_bod NAO derivada por corte em dateAdded: as fontes oficiais confirmam a substituicao da BOD 22-01 pela 26-04 em 10/06/2026, mas nao sustentam usar essa data para classificar cada registro do KEV",
        "knownRansomwareCampaignUse mantido no valor original; 'Unknown' nao foi reinterpretado como 'No'",
        "cwes e notes mantidas como texto nao-atomico por enquanto: nenhuma analise planejada ate agora exige separa-las",
    ])


if __name__ == "__main__":
    main()
