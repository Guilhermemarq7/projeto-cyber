import json
from pathlib import Path

import pandas as pd

import limpeza
import utils

BRONZE = Path("dados/bronze/nvd")
PRATA = Path("dados/prata")
ANOS = [2024, 2025, 2026]

STATUS_ESPERADOS = {
    "Received",
    "Awaiting Analysis",
    "Undergoing Analysis",
    "Analyzed",
    "Modified",
    "Deferred",
    "Rejected",
}

ORDEM_CVSS = (
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2",
)

FONTE_NVD = "nvd@nist.gov"


def descricao_en(cve: dict):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value")

    return None


def _chave_desempate_metrica(metrica):
        # Cria uma chave fixa para desempatar metricas CVSS
        # que ainda ficaram equivalentes pelos criterios anteriores.
    dados = metrica.get("cvssData", {})

    return (
        str(metrica.get("source") or "").casefold(),
        str(metrica.get("type") or "").casefold(),
        str(dados.get("vectorString") or ""),
        str(dados.get("baseScore")),
    )


def selecionar_metrica_cvss(cve: dict):
        # Escolhe uma metrica CVSS para representar a CVE.
        # Tenta a versao mais nova, prefere Primary e depois fonte NVD.
        # Se ainda houver mais de uma candidata, marca como ambiguo
        # e usa uma regra fixa de desempate.
    metricas = cve.get("metrics", {})

    for versao in ORDEM_CVSS:
        lista = metricas.get(versao, [])

        validas = [
            metrica
            for metrica in lista
            if metrica.get("cvssData", {}).get("baseScore") is not None
        ]

        if not validas:
            continue

        primarias = [
            metrica
            for metrica in validas
            if metrica.get("type") == "Primary"
        ]
        candidatas = primarias or validas

        da_nvd = [
            metrica
            for metrica in candidatas
            if str(metrica.get("source") or "").casefold() == FONTE_NVD
        ]
        candidatas = da_nvd or candidatas

        selecao_ambigua = len(candidatas) > 1

        escolhida = min(
            candidatas,
            key=_chave_desempate_metrica,
        )

        dados = escolhida.get("cvssData", {})
        score = dados.get("baseScore")

        if versao == "cvssMetricV2":
            severidade = escolhida.get("baseSeverity")
        else:
            severidade = dados.get("baseSeverity")

        return (
            score,
            severidade,
            versao,
            escolhida.get("source"),
            escolhida.get("type"),
            dados.get("vectorString"),
            len(validas),
            selecao_ambigua,
        )

    return None, None, None, None, None, None, 0, False


def cwes(cve: dict):
        # Extrai os codigos CWE em ingles, evita duplicados
        # e junta os valores encontrados em uma unica string.
    codigos = []

    for fraqueza in cve.get("weaknesses", []):
        for desc in fraqueza.get("description", []):
            if desc.get("lang") == "en":
                valor = desc.get("value")

                if valor and valor not in codigos:
                    codigos.append(valor)

    return ", ".join(codigos) if codigos else None


def carregar():
    registros = []
    origens = []

    for ano in ANOS:
        caminho = utils.mais_recente(
            BRONZE,
            f"nvd_{ano}_*.json",
        )

        origens.append(caminho.name)

        with caminho.open("r", encoding="utf-8") as f:
            dados_brutos = json.load(f)

        for item in dados_brutos.get("vulnerabilities", []):
            cve = item["cve"]

            (
                score,
                severidade,
                versao_cvss,
                fonte_cvss,
                tipo_cvss,
                vetor_cvss,
                num_metricas_cvss,
                selecao_ambigua,
            ) = selecionar_metrica_cvss(cve)

            registros.append(
                {
                    "id": cve.get("id"),
                    "sourceIdentifier": cve.get("sourceIdentifier"),
                    "published": cve.get("published"),
                    "lastModified": cve.get("lastModified"),
                    "vulnStatus": cve.get("vulnStatus"),
                    "descricao_en": descricao_en(cve),
                    "baseScore": score,
                    "baseSeverity": severidade,
                    "cvss_versao_usada": versao_cvss,
                    "cvss_source": fonte_cvss,
                    "cvss_type": tipo_cvss,
                    "cvss_vector": vetor_cvss,
                    "cvss_num_metricas_na_versao": num_metricas_cvss,
                    "cvss_selecao_ambigua": selecao_ambigua,
                    "num_referencias": len(cve.get("references", [])),
                    "num_fraquezas": len(cve.get("weaknesses", [])),
                    "cwes": cwes(cve),
                }
            )

    df = pd.DataFrame(registros)

    print("lido:", ", ".join(origens), df.shape)
    print(df.columns.tolist())
    print(df.isna().sum())

    return df, origens


def diagnosticar_ausentes_por_status(df):
    # Mostra em quais vulnStatus estao os CVEs que ficaram sem baseScore.
    sem_score = df[df["baseScore"].isna()]
    contagem = sem_score["vulnStatus"].value_counts()

    print("\nCVEs sem baseScore, por vulnStatus:")
    print(contagem)
    print(f"Total sem baseScore: {len(sem_score)}\n")

    return contagem.to_dict()


def conferir_vulnstatus(df):
    # Compara os vulnStatus encontrados com os valores esperados
    # e retorna qualquer status que nao estava previsto.
    inesperados = sorted(
        set(df["vulnStatus"].dropna().unique())
        - STATUS_ESPERADOS
    )

    print(
        "valores nao previstos em vulnStatus:",
        inesperados or "nenhum",
    )

    return inesperados


def tratar_rejeitados(df):
        # Remove os CVEs com vulnStatus Rejected
        # e retorna quantos registros foram removidos.
    rejeitados = df["vulnStatus"] == "Rejected"
    quantidade = int(rejeitados.sum())

    print("rejeitados removidos:", quantidade)

    return df.loc[~rejeitados].copy(), quantidade


def sinalizar_sem_cvss(df):
        # Cria uma flag para identificar CVEs mantidos sem pontuacao CVSS
        # e retorna quantos casos existem.
    df["sem_pontuacao_cvss"] = df["baseScore"].isna()
    quantidade = int(df["sem_pontuacao_cvss"].sum())

    print(
        "sem pontuacao CVSS (mantidos e sinalizados):",
        quantidade,
    )

    return df, quantidade


def derivar_vetor_ataque_rede(df):
        # Cria uma coluna derivada indicando se o vetor CVSS possui AV:N,
        # ou seja, se o Attack Vector da metrica selecionada e Network.
    df["vetor_ataque_rede"] = pd.Series(
        pd.NA,
        index=df.index,
        dtype="boolean",
    )

    possui_vetor = df["cvss_vector"].notna()

    df.loc[possui_vetor, "vetor_ataque_rede"] = (
        df.loc[possui_vetor, "cvss_vector"]
        .str.contains(r"(?:^|/)AV:N(?:/|$)", regex=True, na=False)
    )

    quantidade_rede = int(
        df["vetor_ataque_rede"].fillna(False).sum()
    )
    quantidade_sem_vetor = int(
        df["vetor_ataque_rede"].isna().sum()
    )

    print(
        "CVEs com vetor de ataque Network (AV:N):",
        quantidade_rede,
    )
    print(
        "CVEs sem vetor CVSS utilizavel para derivar a flag:",
        quantidade_sem_vetor,
    )

    return df, quantidade_rede, quantidade_sem_vetor


def marcar_extremos_referencias(df):
        # Usa os limites do IQR para sinalizar valores extremos
        # em num_referencias, sem remover essas linhas.
    baixo, alto = limpeza.limites_iqr(
        df["num_referencias"]
    )

    df["num_referencias_extremo"] = (
        (df["num_referencias"] < baixo)
        | (df["num_referencias"] > alto)
    )

    quantidade = int(df["num_referencias_extremo"].sum())

    print(
        "num_referencias extremos sinalizados pelo IQR:",
        quantidade,
    )

    return df, quantidade


def converter_tipos(df):
        # Converte published e lastModified para datetime,
        # identifica falhas de conversao e remove apenas essas linhas.
    novos_ausentes = {}
    falhas_conversao = pd.Series(False, index=df.index)

    for coluna in ["published", "lastModified"]:
        ausentes_antes = df[coluna].isna()

        df[coluna] = pd.to_datetime(
            df[coluna],
            errors="coerce",
            utc=True,
        )

        falhas_coluna = (
            ~ausentes_antes
            & df[coluna].isna()
        )

        novos = int(falhas_coluna.sum())
        novos_ausentes[coluna] = novos
        falhas_conversao |= falhas_coluna

        print(
            f"{coluna}: novos ausentes apos conversao de data:",
            novos,
        )

    removidas_conversao = int(falhas_conversao.sum())

    if removidas_conversao:
        print(
            "linhas removidas por falha de conversao de data:",
            removidas_conversao,
        )
        print(
            df.loc[
                falhas_conversao,
                ["id", "published", "lastModified"],
            ]
        )
        df = df.loc[~falhas_conversao].copy()

    return df, novos_ausentes, removidas_conversao


def salvar(df):
    PRATA.mkdir(parents=True, exist_ok=True)

    destino = PRATA / "nvd.parquet"
    df.to_parquet(destino, index=False)

    print("salvo em:", destino, df.shape)

    return destino


def main():
    df, origens = carregar()
    antes = len(df)

    df = limpeza.tirar_espacos(df)

    df, duplicadas = limpeza.conferir_chave(
        df,
        chave="id",
    )

    inesperados = conferir_vulnstatus(df)

    df, rejeitados = tratar_rejeitados(df)

    df, novos_ausentes_data, removidas_datas = converter_tipos(df)

    df, fora_faixa_score = limpeza.validar_faixa(
        df,
        "baseScore",
        0,
        10,
        remover=True,
    )

    diagnosticar_ausentes_por_status(df)

    df, sem_cvss = sinalizar_sem_cvss(df)

    (
        df,
        vetor_ataque_rede,
        vetor_ataque_rede_ausente,
    ) = derivar_vetor_ataque_rede(df)

    df, extremos_referencias = marcar_extremos_referencias(df)

    multiplas_metricas = int(
        (df["cvss_num_metricas_na_versao"] > 1).sum()
    )

    selecoes_ambiguas = int(
        df["cvss_selecao_ambigua"].sum()
    )

    destino = salvar(df)

    inesperados_txt = (
        ", ".join(inesperados)
        if inesperados
        else "nenhum"
    )

    utils.registrar(
        PRATA,
        origens,
        destino,
        antes,
        len(df),
        [
            "espacos removidos de colunas de texto antes da conferencia da chave",
            (
                "chave 'id' conferida apos concatenar os 3 anos: "
                f"{duplicadas} duplicata(s) encontrada(s) e removida(s)"
            ),
            (
                "vulnStatus conferido contra os valores esperados pelo projeto; "
                f"valores nao previstos: {inesperados_txt}"
            ),
            f"CVEs Rejected removidos: {rejeitados}",
            (
                "published e lastModified convertidos para datetime UTC; "
                f"falhas de conversao: published={novos_ausentes_data['published']}, "
                f"lastModified={novos_ausentes_data['lastModified']}; "
                f"linhas removidas por falha de conversao={removidas_datas}"
            ),
            (
                "baseScore validado no dominio 0-10; "
                f"{fora_faixa_score} linha(s) com score fora da faixa removida(s)"
            ),
            (
                "CVEs mantidos sem baseScore foram sinalizados em "
                f"sem_pontuacao_cvss: {sem_cvss}"
            ),
            (
                "atributo derivado vetor_ataque_rede criado a partir do "
                "componente AV da metrica CVSS selecionada; "
                f"AV:N={vetor_ataque_rede}, "
                f"sem vetor utilizavel={vetor_ataque_rede_ausente}; "
                "a flag descreve Attack Vector=Network e nao significa, "
                "por si so, exploracao bem-sucedida"
            ),
            (
                "num_referencias teve extremos apenas sinalizados pelo criterio "
                f"de 1,5 x IQR: {extremos_referencias} registro(s); "
                "nenhuma linha foi removida por esse criterio"
            ),
            (
                "politica LOCAL de selecao CVSS: prefere a versao mais nova "
                "disponivel; dentro da versao prefere metricas Primary; "
                "entre candidatas equivalentes prefere source nvd@nist.gov; "
                "empates remanescentes sao resolvidos de forma deterministica "
                "e marcados em cvss_selecao_ambigua"
            ),
            (
                "metadados da metrica CVSS selecionada preservados em "
                "cvss_source, cvss_type, cvss_vector e "
                "cvss_num_metricas_na_versao"
            ),
            (
                "registros com mais de uma metrica CVSS valida na versao "
                f"selecionada: {multiplas_metricas}"
            ),
            (
                "registros cuja selecao permaneceu ambigua apos as preferencias "
                f"locais: {selecoes_ambiguas}"
            ),
            (
                "codigos CWE extraidos como texto na coluna cwes, alem da "
                "contagem em num_fraquezas"
            ),
            (
                "arquivos NVD de 2024, 2025 e 2026 concatenados em uma unica "
                "tabela da camada Prata"
            ),
        ],
    )


if __name__ == "__main__":
    main()
