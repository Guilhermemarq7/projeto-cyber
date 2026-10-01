"""Funcoes genericas de limpeza e validacao de dados."""


def conferir_chave(df, chave):
    envolvidas = df[chave].duplicated(keep=False)

    resultado = df.drop_duplicates(subset=chave).copy()
    quantidade = len(df) - len(resultado)

    print(f"chaves repetidas ({chave}):", quantidade)

    if quantidade:
        print(df.loc[envolvidas])

    return resultado, quantidade


def tirar_espacos(df):
    df.columns = df.columns.str.strip()

    for coluna in df.select_dtypes(include="object"):
        df[coluna] = df[coluna].str.strip()

    return df


def validar_faixa(df, coluna, minimo, maximo, remover=False):
    fora_da_faixa = (
        df[coluna].notna()
        & ~df[coluna].between(minimo, maximo)
    )

    quantidade = int(fora_da_faixa.sum())

    print(f"{coluna} fora de [{minimo}, {maximo}]:", quantidade)

    if quantidade:
        print(df.loc[fora_da_faixa])

    if remover and quantidade:
        df = df.loc[~fora_da_faixa].copy()
        print(f"linhas removidas por {coluna} fora da faixa:", quantidade)

    return df, quantidade


def validar_ordem_datas(df, coluna_inicio, coluna_fim):
    ambas_preenchidas = (
        df[coluna_inicio].notna()
        & df[coluna_fim].notna()
    )

    invertidas = (
        ambas_preenchidas
        & (df[coluna_fim] < df[coluna_inicio])
    )

    quantidade = int(invertidas.sum())

    print(f"{coluna_fim} antes de {coluna_inicio}:", quantidade)

    if quantidade:
        print(df.loc[invertidas, [coluna_inicio, coluna_fim]])

    return df, quantidade


def limites_iqr(serie):
    q1 = serie.quantile(0.25)
    q3 = serie.quantile(0.75)
    iqr = q3 - q1

    return q1 - 1.5 * iqr, q3 + 1.5 * iqr
