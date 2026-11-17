import logging
from config import BRONZE_CISA_KEV as BRONZE, PRATA, configurar_log

import pandas as pd

import limpeza
import utils

PADRAO = "cisa_kev_*.csv"
log = logging.getLogger(__name__)


def carregar():
    caminho = utils.mais_recente(BRONZE, PADRAO)
    df = pd.read_csv(caminho)


    log.info(
        "CISA KEV carregado: arquivo=%s; linhas=%s; colunas=%s",
        caminho.name,
        len(df),
        len(df.columns),
    )

    log.debug(
        "Colunas do CISA KEV: %s",
        df.columns.tolist(),
    )

    log.info(
        "Valores ausentes por coluna no CISA KEV: %s",
        df.isna().sum().to_dict(),
    )


    return df, caminho



def converter_tipos(df):
    # Converte dateAdded e dueDate para datetime e conta
    # quantos novos valores ausentes surgiram na conversao.
    novos_ausentes = {}

    for coluna in ["dateAdded", "dueDate"]:
        antes = int(df[coluna].isna().sum())

        df[coluna] = pd.to_datetime(
            df[coluna],
            format="%Y-%m-%d",
            errors="coerce",
        )

        depois = int(df[coluna].isna().sum())
        novos = max(0, depois - antes)

        novos_ausentes[coluna] = novos

        log.info(
            "%s: novos ausentes apos conversao de data: %s",
            coluna,
            novos,
        )

    return df, novos_ausentes




def salvar(df):
    PRATA.mkdir(parents=True, exist_ok=True)

    destino = PRATA / "cisa_kev.parquet"
    df.to_parquet(destino, index=False)

    log.info(
        "CISA KEV salvo em: %s; linhas=%s; colunas=%s",
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
        chave="cveID",
    )

    df, novos_ausentes = converter_tipos(df)

    df, datas_invertidas = limpeza.validar_ordem_datas(
        df,
        "dateAdded",
        "dueDate",
    )

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
                f"chave 'cveID' conferida: "
                f"{duplicadas} duplicata(s) encontrada(s) e removida(s)"
            ),
            (
                "dateAdded e dueDate convertidos para datetime; "
                f"novos ausentes criados pela conversao: "
                f"dateAdded={novos_ausentes['dateAdded']}, "
                f"dueDate={novos_ausentes['dueDate']}"
            ),
            (
                f"ordem temporal conferida: "
                f"{datas_invertidas} caso(s) com dueDate anterior a dateAdded"
            ),
            (
                "dateAdded mantida como data de inclusao no catalogo, "
                "nao como data da primeira exploracao"
            ),
            (
                "dueDate mantida como prazo de remediacao publicado pela CISA, "
                "nao como atributo tecnico da vulnerabilidade"
            ),
            (
                "knownRansomwareCampaignUse mantido no valor original; "
                "'Unknown' nao foi reinterpretado como 'No'"
            ),
            "cwes e notes mantidas como texto nao-atomico por enquanto",
        ],
    )


if __name__ == "__main__":
    configurar_log()
    main()
