import json
from pathlib import Path

import pandas as pd

import limpeza
import utils

BRONZE = Path("dados/bronze/nvd")
PRATA = Path("dados/prata")
ANOS = [2024, 2025, 2026]

# Valores atualmente documentados pelo NVD para vulnStatus/API.
# O schema aceita string aberta, entao a lista serve como alarme para valor novo,
# nao como prova de que qualquer valor diferente seja automaticamente invalido.
STATUS_ESPERADOS = {
    "Received", "Awaiting Analysis", "Undergoing Analysis",
    "Analyzed", "Modified", "Deferred", "Rejected",
}

# Politica LOCAL do projeto para reduzir varias metricas CVSS a uma unica coluna.
# Nao e uma prioridade oficial do NVD. Mantemos a mesma regra usada na
# exploracao da Aula 4 para nao mudar o significado de baseScore no meio do
# projeto: versao mais nova disponivel e, dentro dela, primeira metrica valida.
# Como a ordem do array nao e uma prioridade oficial, tambem preservamos source,
# type, vectorString e a quantidade de metricas para tornar a escolha auditavel.
ORDEM_CVSS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def descricao_en(cve: dict):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value")
    return None


def selecionar_metrica_cvss(cve: dict):
    """Seleciona uma metrica CVSS pela politica local ja usada na Aula 4.

    Politica do projeto:
    1. prefere a versao mais nova disponivel (4.0 > 3.1 > 3.0 > 2.0);
    2. dentro da versao, usa a primeira metrica que possui baseScore.

    O passo 2 NAO e uma precedencia oficial do NVD. Ele e mantido aqui para
    preservar consistencia com o perfilamento ja feito. Por isso retornamos
    tambem source, type, vectorString e a quantidade de metricas validas na
    versao escolhida; se houver mais de uma, a selecao fica explicitamente
    marcada como um ponto a investigar antes da modelagem.
    """
    metricas = cve.get("metrics", {})

    for versao in ORDEM_CVSS:
        lista = metricas.get(versao, [])
        validas = [
            m for m in lista
            if m.get("cvssData", {}).get("baseScore") is not None
        ]
        if not validas:
            continue

        escolhida = validas[0]
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
        )

    return None, None, None, None, None, None, 0


def cwes(cve: dict):
    codigos = []
    for fraqueza in cve.get("weaknesses", []):
        for desc in fraqueza.get("description", []):
            if desc.get("lang") == "en":
                valor = desc.get("value")
                if valor and valor not in codigos:
                    codigos.append(valor)
    return ", ".join(codigos) if codigos else None


def carregar():
    # Os arquivos 2024/2025/2026 sao particoes complementares por prefixo
    # do identificador CVE. Para cada ano, usamos a extracao bronze mais recente.
    registros = []
    origens = []

    for ano in ANOS:
        caminho = utils.mais_recente(BRONZE, f"nvd_{ano}_*.json")
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
            ) = selecionar_metrica_cvss(cve)

            registros.append({
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
                "num_referencias": len(cve.get("references", [])),
                "num_fraquezas": len(cve.get("weaknesses", [])),
                "cwes": cwes(cve),
            })

    df = pd.DataFrame(registros)
    print("lido:", ", ".join(origens), df.shape)
    print(df.columns.tolist())
    print(df.isna().sum())
    return df, origens


def diagnosticar_ausentes_por_status(df):
    """Mostra os status dos CVEs validos que continuam sem baseScore."""
    sem_score = df[df["baseScore"].isna()]
    contagem = sem_score["vulnStatus"].value_counts()
    print("\nCVEs nao rejeitados sem baseScore, por vulnStatus:")
    print(contagem)
    print(f"Total nao rejeitado sem baseScore: {len(sem_score)}\n")
    return contagem.to_dict()


def conferir_vulnstatus(df):
    """Avisa sobre status fora da lista atualmente documentada pelo NVD."""
    inesperados = sorted(
        set(df["vulnStatus"].dropna().unique()) - STATUS_ESPERADOS
    )
    print("valores nao previstos em vulnStatus:", inesperados or "nenhum")
    return inesperados


def tratar_rejeitados(df):
    """Remove CVEs com vulnStatus='Rejected', que nao sao registros CVE validos."""
    e_rejeitado = df["vulnStatus"] == "Rejected"
    print("rejeitados removidos:", int(e_rejeitado.sum()))
    return df[~e_rejeitado].copy()


def sinalizar_sem_cvss(df):
    """Mantem CVEs validos sem score e cria uma flag de qualidade.

    A ausencia de score nao tem uma unica causa: pode estar ligada ao estado de
    enriquecimento, a politica do NVD, a versao disponivel ou a fonte da metrica.
    Por isso nao preenchemos nem removemos automaticamente.
    """
    df["sem_pontuacao_cvss"] = df["baseScore"].isna()
    print(
        "sem pontuacao CVSS (mantidos e sinalizados):",
        int(df["sem_pontuacao_cvss"].sum()),
    )
    return df


def marcar_extremos_referencias(df):
    """Marca extremos de num_referencias pelo IQR, sem remover as linhas."""
    baixo, alto = limpeza.limites_iqr(df["num_referencias"])
    df["num_referencias_extremo"] = (
        (df["num_referencias"] < baixo) | (df["num_referencias"] > alto)
    )
    print(
        "num_referencias extremos persistidos pelo IQR:",
        int(df["num_referencias_extremo"].sum()),
    )
    return df


def converter_tipos(df):
    """Converte datas NVD e mede se a conversao criou novos ausentes."""
    novos_ausentes = {}

    for coluna in ["published", "lastModified"]:
        antes = int(df[coluna].isna().sum())
        df[coluna] = pd.to_datetime(df[coluna], errors="coerce", utc=True)
        depois = int(df[coluna].isna().sum())
        novos = max(0, depois - antes)
        novos_ausentes[coluna] = novos
        print(f"{coluna}: novos ausentes apos conversao de data:", novos)

    return df, novos_ausentes


def salvar(df):
    PRATA.mkdir(parents=True, exist_ok=True)
    destino = PRATA / "nvd.parquet"
    df.to_parquet(destino, index=False)
    print("salvo em:", destino, df.shape)
    return destino


def main():
    df, origens = carregar()
    antes = len(df)

    # Normaliza texto antes de conferir a chave, para nao esconder duplicata
    # causada apenas por espaco sobrando.
    df = limpeza.tirar_espacos(df)
    duplicadas = int(df["id"].duplicated().sum())
    df = limpeza.conferir_chave(df, chave="id")

    inesperados = conferir_vulnstatus(df)

    fora_faixa_score = int(
        (df["baseScore"].notna() & ~df["baseScore"].between(0, 10)).sum()
    )
    limpeza.validar_faixa(df, "baseScore", 0, 10)

    rejeitados = int((df["vulnStatus"] == "Rejected").sum())
    df = tratar_rejeitados(df)

    # Agora o diagnostico responde exatamente sobre os CVEs que sobraram
    # depois da remocao dos Rejected.
    diagnosticar_ausentes_por_status(df)
    df = sinalizar_sem_cvss(df)
    sem_cvss = int(df["sem_pontuacao_cvss"].sum())

    # Aula 5: compara os dois metodos, mas persiste apenas a flag por IQR.
    comparacao_extremos = limpeza.comparar_iqr_zscore(
        df, "num_referencias", limite_z=3
    )
    df = marcar_extremos_referencias(df)

    multiplas_metricas = int((df["cvss_num_metricas_na_versao"] > 1).sum())

    df, novos_ausentes_data = converter_tipos(df)

    destino = salvar(df)
    inesperados_txt = ", ".join(inesperados) if inesperados else "nenhum"

    utils.registrar(PRATA, origens, destino, antes, len(df), [
        "espacos removidos de colunas de texto antes da conferencia da chave",
        f"chave 'id' conferida apos concatenar os 3 anos: {duplicadas} duplicata(s) encontrada(s) e removida(s)",
        f"vulnStatus conferido contra os 7 valores atualmente documentados pelo NVD; valores nao previstos: {inesperados_txt}",
        f"baseScore validado na faixa 0-10: {fora_faixa_score} valor(es) fora da faixa",
        f"CVEs Rejected removidos: {rejeitados}",
        f"CVEs validos sem baseScore mantidos e sinalizados em sem_pontuacao_cvss: {sem_cvss}",
        (
            "num_referencias comparado por IQR e z-score sem persistir a coluna z: "
            f"IQR={comparacao_extremos['iqr']}, z-score={comparacao_extremos['zscore']}, "
            f"somente IQR={comparacao_extremos['so_iqr']}, somente z-score={comparacao_extremos['so_zscore']}; "
            "a flag persistida no Parquet e a do IQR"
        ),
        (
            "published e lastModified convertidos para datetime UTC; "
            f"novos ausentes criados pela conversao: published={novos_ausentes_data['published']}, "
            f"lastModified={novos_ausentes_data['lastModified']}"
        ),
        (
            "CVSS reduzido a um score pela mesma politica LOCAL usada no perfilamento da Aula 4: "
            "versao mais nova disponivel e primeira metrica valida nessa versao. "
            "A ordem do array nao e uma precedencia oficial do NVD; source, type e vectorString foram preservados para auditoria"
        ),
        f"registros com mais de uma metrica CVSS valida na versao selecionada: {multiplas_metricas}",
        "versao, source, type e vectorString da metrica CVSS selecionada foram preservados; scores de versoes diferentes nao devem ser tratados como escala estatistica intercambiavel sem controle",
        "codigos CWE extraidos como texto (coluna cwes), alem da contagem existente em num_fraquezas",
        "arquivos dos 3 anos (2024, 2025, 2026) concatenados; os feeds anuais sao particionados pelo prefixo do CVE, nao pela data published",
    ])


if __name__ == "__main__":
    main()
