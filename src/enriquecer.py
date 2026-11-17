import logging

import pandas as pd

from config import PRATA, configurar_log
import utils

log = logging.getLogger(__name__)


def carregar():
    caminhos = {
        "NVD": PRATA / "nvd.parquet",
        "EPSS": PRATA / "epss.parquet",
        "CISA KEV": PRATA / "cisa_kev.parquet",
    }

    for nome, caminho in caminhos.items():
        if not caminho.is_file():
            raise FileNotFoundError(
                f"Parquet da fonte {nome} nao encontrado: {caminho}"
            )

    nvd = pd.read_parquet(caminhos["NVD"])
    epss = pd.read_parquet(caminhos["EPSS"])
    kev = pd.read_parquet(caminhos["CISA KEV"])


    for nome, df in [
        ("NVD", nvd),
        ("EPSS", epss),
        ("CISA KEV", kev),
    ]:
        log.info(
            "%s carregada: %s linhas",
            nome,
            len(df),
        )

        if df.empty:
            raise ValueError(f"A tabela da fonte {nome} esta vazia")

    return nvd, epss, kev


def conferir_chave(df, nome, chave, colunas):
    # Verifica a estrutura e a qualidade da chave antes da juncao.
    faltando = [coluna for coluna in colunas if coluna not in df.columns]

    if faltando:
        raise ValueError(f"{nome}: colunas ausentes: {faltando}")

    if not df[chave].dropna().map(lambda valor: isinstance(valor, str)).all():
        raise ValueError(f"{nome}: a chave {chave} contem valores que nao sao texto")

    ausentes = df[chave].isna() | df[chave].astype("string").str.strip().eq("").fillna(
        False
    )

    duplicadas = int(df[chave].duplicated().sum())


    log.info(
        "%s: chave=%s; vazias=%s; duplicadas=%s",
        nome,
        chave,
        int(ausentes.sum()),
        duplicadas,
    )


    if ausentes.any() or duplicadas:
        raise ValueError(f"{nome}: corrija as chaves invalidas antes da juncao")


def conferir_correspondencias(nvd, epss, kev):
    # Compara as chaves antes de qualquer merge.
    ids_nvd = set(nvd["id"])
    ids_epss = set(epss["cve"])
    ids_kev = set(kev["cveID"])

    log.info("NVD x EPSS (antes da juncao)")
    log.info("So na NVD: %s", len(ids_nvd - ids_epss))
    log.info("So no EPSS: %s", len(ids_epss - ids_nvd))
    log.info("Nos dois: %s", len(ids_nvd & ids_epss))
    log.info(
        "Exemplos so no EPSS: %s",
        sorted(ids_epss - ids_nvd)[:5],
    )

    log.info("NVD x KEV (antes da juncao)")
    log.info("So na NVD: %s", len(ids_nvd - ids_kev))
    log.info("So no KEV: %s", len(ids_kev - ids_nvd))
    log.info("Nos dois: %s", len(ids_nvd & ids_kev))
    log.info(
        "Exemplos so no KEV: %s",
        sorted(ids_kev - ids_nvd)[:5],
    )


def juntar(nvd, epss, kev):
    # Usa somente as colunas necessarias das fontes secundarias.
    epss_usado = epss[["cve", "epss", "percentile"]]

    kev_usado = kev[["cveID", "dateAdded", "knownRansomwareCampaignUse"]].rename(
        columns={
            "dateAdded": "kev_dateAdded",
            "knownRansomwareCampaignUse": "kev_knownRansomwareCampaignUse",
        }
    )

    # Primeira juncao: preserva todas as CVEs da NVD.
    resultado = nvd.merge(
        epss_usado,
        left_on="id",
        right_on="cve",
        how="left",
        validate="one_to_one",
        indicator="_merge_epss",
    )

    resultado["tem_epss"] = resultado["_merge_epss"].eq("both")

    resultado = resultado.drop(columns=["cve", "_merge_epss"])

    if len(resultado) != len(nvd):
        raise ValueError("A juncao com EPSS alterou o numero de CVEs da NVD")

    # Segunda juncao: identifica a presenca no catalogo KEV.
    resultado = resultado.merge(
        kev_usado,
        left_on="id",
        right_on="cveID",
        how="left",
        validate="one_to_one",
        indicator="_merge_kev",
    )

    resultado["consta_kev"] = resultado["_merge_kev"].eq("both")

    resultado = resultado.drop(columns=["cveID", "_merge_kev"])

    return resultado


def derivar_atributo(resultado):
    # Combina severidade CVSS (NVD) e percentil EPSS.
    # Mantem ausente quando faltar alguma informacao necessaria.
    if "baseSeverity" not in resultado.columns:
        raise ValueError("A coluna baseSeverity nao existe na NVD")

    resultado["cvss_alto_epss_top10"] = pd.Series(
        pd.NA,
        index=resultado.index,
        dtype="boolean",
    )

    completos = resultado["baseSeverity"].notna() & resultado["percentile"].notna()

    resultado.loc[completos, "cvss_alto_epss_top10"] = resultado.loc[
        completos, "baseSeverity"
    ].isin(["HIGH", "CRITICAL"]) & resultado.loc[completos, "percentile"].ge(0.90)

    return resultado


def validar(nvd, resultado):
    log.info("VALIDACAO DO ENRIQUECIMENTO")
    log.info("NVD antes: %s", len(nvd))
    log.info("Resultado: %s", len(resultado))

    if len(resultado) != len(nvd) or resultado["id"].duplicated().any():
        raise ValueError("A juncao alterou a quantidade ou a unicidade das CVEs")

    sem_epss = int((~resultado["tem_epss"]).sum())

    com_kev = int(resultado["consta_kev"].sum())

    sem_kev = int((~resultado["consta_kev"]).sum())

    atributo_verdadeiro = int(resultado["cvss_alto_epss_top10"].fillna(False).sum())

    atributo_ausente = int(resultado["cvss_alto_epss_top10"].isna().sum())

    log.info("NVD sem correspondencia no EPSS: %s", sem_epss)
    log.info("NVD com correspondencia no KEV: %s", com_kev)
    log.info("NVD sem correspondencia no KEV: %s", sem_kev)

    log.info(
        "Exemplos sem EPSS: %s",
        resultado.loc[~resultado["tem_epss"], "id"].head(5).tolist(),
    )

    log.info(
        "Exemplos sem KEV: %s",
        resultado.loc[~resultado["consta_kev"], "id"].head(5).tolist(),
    )

    log.info("cvss_alto_epss_top10=True: %s", atributo_verdadeiro)
    log.info("cvss_alto_epss_top10 ausente: %s", atributo_ausente)

    return (
        sem_epss,
        com_kev,
        sem_kev,
        atributo_verdadeiro,
        atributo_ausente,
    )


def salvar(resultado):
    destino = PRATA / "vulnerabilidades_enriquecidas.parquet"

    resultado.to_parquet(destino, index=False)

    log.info(
        "Enriquecimento salvo em: %s; linhas=%s; colunas=%s",
        destino,
        len(resultado),
        len(resultado.columns),
    )

    return destino


def main():
    nvd, epss, kev = carregar()

    conferir_chave(
        nvd,
        "NVD",
        "id",
        ["id", "baseSeverity"],
    )

    conferir_chave(
        epss,
        "EPSS",
        "cve",
        ["cve", "epss", "percentile"],
    )

    conferir_chave(
        kev,
        "CISA KEV",
        "cveID",
        ["cveID", "dateAdded", "knownRansomwareCampaignUse"],
    )

    conferir_correspondencias(nvd, epss, kev)

    resultado = juntar(nvd, epss, kev)

    resultado = derivar_atributo(resultado)

    (
        sem_epss,
        com_kev,
        sem_kev,
        atributo_verdadeiro,
        atributo_ausente,
    ) = validar(nvd, resultado)

    destino = salvar(resultado)

    utils.registrar(
        PRATA,
        [
            "nvd.parquet",
            "epss.parquet",
            "cisa_kev.parquet",
        ],
        destino,
        len(nvd),
        len(resultado),
        [
            (
                "base NVD: uma linha por CVE; "
                "juncao left com EPSS por id=cve "
                "e com KEV por id=cveID"
            ),
            (
                "ambas as juncoes com validate=one_to_one; "
                "contagem de linhas e unicidade conferidas"
            ),
            f"NVD sem correspondencia EPSS: {sem_epss}",
            (f"NVD presente no KEV: {com_kev}; " f"NVD ausente no KEV: {sem_kev}"),
            (
                "consta_kev significa presenca no catalogo, "
                "nao ausencia comprovada de exploracao"
            ),
            (
                "tem_epss indica correspondencia; "
                "EPSS ausente nao foi preenchido com zero"
            ),
            (
                "cvss_alto_epss_top10: severidade HIGH/CRITICAL "
                "e percentile EPSS >= 0.90; "
                f"verdadeiros={atributo_verdadeiro}; "
                f"ausentes={atributo_ausente}; "
                "limiar exploratorio, nao previsao de exploracao"
            ),
            (
                "KEV dateAdded e data de inclusao no catalogo, "
                "nao da primeira exploracao"
            ),
        ],
    )


if __name__ == "__main__":
    configurar_log()
    main()
