"""Funcoes de limpeza e validacao que servem a qualquer fonte.

Diferente de utils.py, tudo aqui trata, confere ou diagnostica dado.
Nenhuma funcao menciona NVD, EPSS ou CISA KEV, por isso podem ser
reaproveitadas nos tres datasets (e em fontes futuras do projeto).
"""

import pandas as pd


def conferir_chave(df, chave):
    """Confere se a coluna 'chave' tem valores repetidos.

    Mostra as repeticoes antes de remover. Chave repetida costuma ser
    sintoma de outro problema, nao a doenca.
    """
    repetidas = df[chave].duplicated().sum()
    print(f"chaves repetidas ({chave}):", repetidas)
    if repetidas:
        print(df[df[chave].duplicated(keep=False)])
    return df.drop_duplicates(subset=chave)


def tirar_espacos(df):
    """Remove espacos sobrando do nome das colunas e do conteudo textual."""
    df.columns = df.columns.str.strip()
    for coluna in df.select_dtypes(include="object"):
        df[coluna] = df[coluna].str.strip()
    return df


def validar_faixa(df, coluna, minimo, maximo):
    """Confere valores nao nulos fora da faixa de dominio informada.

    A funcao apenas mede e mostra. Ela nao remove sozinha porque a decisao
    de tratamento deve ser tomada depois de identificar a causa.
    """
    preenchidos = df[coluna].dropna()
    fora_da_faixa = ~preenchidos.between(minimo, maximo)
    quantidade = int(fora_da_faixa.sum())

    print(f"{coluna} fora de [{minimo}, {maximo}]:", quantidade)
    if quantidade:
        print(df.loc[preenchidos[fora_da_faixa].index])
    return df


def validar_ordem_datas(df, coluna_inicio, coluna_fim):
    """Confere se coluna_fim nunca vem antes de coluna_inicio.

    Apenas mede e mostra; nao corrige nem remove automaticamente.
    """
    ambas_preenchidas = df[coluna_inicio].notna() & df[coluna_fim].notna()
    invertidas = ambas_preenchidas & (df[coluna_fim] < df[coluna_inicio])
    quantidade = int(invertidas.sum())

    print(f"{coluna_fim} antes de {coluna_inicio}:", quantidade)
    if quantidade:
        print(df.loc[invertidas, [coluna_inicio, coluna_fim]])
    return df


def limites_iqr(serie):
    """Calcula os limites de valores extremos pelo criterio de 1,5 * IQR."""
    q1 = serie.quantile(0.25)
    q3 = serie.quantile(0.75)
    iqr = q3 - q1
    return q1 - 1.5 * iqr, q3 + 1.5 * iqr


def comparar_iqr_zscore(df, coluna, limite_z=3):
    """Compara IQR e z-score sem criar colunas persistentes no DataFrame.

    A comparacao segue o objetivo da Aula 5: observar onde os metodos
    discordam antes de decidir qual sinalizacao faz mais sentido para a
    distribuicao e para o dominio.
    """
    serie = df[coluna].dropna()
    if serie.empty:
        resultado = {
            "iqr": 0,
            "zscore": 0,
            "so_iqr": 0,
            "so_zscore": 0,
        }
        print(coluna, "sem valores preenchidos para comparar IQR e z-score")
        return resultado

    baixo, alto = limites_iqr(serie)
    mascara_iqr = (serie < baixo) | (serie > alto)

    desvio = serie.std()
    if pd.isna(desvio) or desvio == 0:
        mascara_z = pd.Series(False, index=serie.index)
    else:
        z = (serie - serie.mean()) / desvio
        mascara_z = z.abs() > limite_z

    resultado = {
        "iqr": int(mascara_iqr.sum()),
        "zscore": int(mascara_z.sum()),
        "so_iqr": int((mascara_iqr & ~mascara_z).sum()),
        "so_zscore": int((~mascara_iqr & mascara_z).sum()),
    }

    print(f"{coluna} extremos por IQR:", resultado["iqr"])
    print(f"{coluna} z-score acima de {limite_z}:", resultado["zscore"])
    print(f"{coluna} marcados so pelo IQR:", resultado["so_iqr"])
    print(f"{coluna} marcados so pelo z-score:", resultado["so_zscore"])
    return resultado
