"""Funcoes genericas de limpeza e validacao de dados."""

import logging

log = logging.getLogger(__name__)


def conferir_chave(df, chave):
    # Verifica valores repetidos na coluna usada como chave,
    # remove as duplicatas e retorna quantas foram removidas.
    envolvidas = df[chave].duplicated(keep=False)

    resultado = df.drop_duplicates(subset=chave).copy()
    quantidade = len(df) - len(resultado)

    log.info("Chaves repetidas (%s): %s", chave, quantidade)

    if quantidade:
        log.warning(
            "Exemplos de chaves repetidas (%s): %s",
            chave,
            df.loc[envolvidas, chave].head(5).tolist(),
        )

    return resultado, quantidade


def tirar_espacos(df):
    # Remove espacos extras dos nomes das colunas
    # e tambem dos valores de texto.
    df.columns = df.columns.str.strip()

    for coluna in df.select_dtypes(include="object"):
        df[coluna] = df[coluna].str.strip()

    return df



def validar_faixa(df, coluna, minimo, maximo, remover=False):
    # Verifica valores fora da faixa esperada e,
    # se remover=True, exclui essas linhas.
    fora_da_faixa = (
        df[coluna].notna()
        & ~df[coluna].between(minimo, maximo)
    )

    quantidade = int(fora_da_faixa.sum())

    log.info(
        "%s fora de [%s, %s]: %s",
        coluna,
        minimo,
        maximo,
        quantidade,
    )

    if quantidade:
        log.warning(
            "Exemplos de valores fora da faixa (%s): %s",
            coluna,
            df.loc[fora_da_faixa, coluna].head(5).tolist(),
        )

    if remover and quantidade:
        df = df.loc[~fora_da_faixa].copy()
        log.warning(
            "Linhas removidas por %s fora da faixa: %s",
            coluna,
            quantidade,
        )

    return df, quantidade



def validar_ordem_datas(df, coluna_inicio, coluna_fim):
    # Verifica se a data final aparece antes da data inicial
    # e conta quantos casos assim existem.
    ambas_preenchidas = df[coluna_inicio].notna() & df[coluna_fim].notna()

    invertidas = ambas_preenchidas & (df[coluna_fim] < df[coluna_inicio])

    quantidade = int(invertidas.sum())

    log.info(
    "%s antes de %s: %s",
    coluna_fim,
    coluna_inicio,
    quantidade,
)

    if quantidade:
        log.warning(
            "Exemplos de datas invertidas:\n%s",
            df.loc[
                invertidas, [coluna_inicio, coluna_fim]
            ].head(5).to_string(index=False),
        )

    return df, quantidade


def limites_iqr(serie):
    # Calcula os limites inferior e superior pelo metodo do IQR,
    # usando 1,5 vezes o intervalo interquartil.
    q1 = serie.quantile(0.25)
    q3 = serie.quantile(0.75)
    iqr = q3 - q1

    return q1 - 1.5 * iqr, q3 + 1.5 * iqr
