import json
from pathlib import Path

import pandas as pd
from data_profiling import ProfileReport

import utils

RELATORIOS = Path("relatorios")

FONTES_CSV = [
    (Path("dados/bronze/cisa_kev"), "cisa_kev_*.csv"),
    (Path("dados/bronze/epss"), "epss_*.csv"),
]

FONTES_NVD = [
    (Path("dados/bronze/nvd"), "nvd_2024_*.json"),
    (Path("dados/bronze/nvd"), "nvd_2025_*.json"),
    (Path("dados/bronze/nvd"), "nvd_2026_*.json"),
]

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
    dados = metrica.get("cvssData", {})

    return (
        str(metrica.get("source") or "").casefold(),
        str(metrica.get("type") or "").casefold(),
        str(dados.get("vectorString") or ""),
        str(dados.get("baseScore")),
    )


def selecionar_metrica_cvss(cve: dict):
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
    codigos = []

    for fraqueza in cve.get("weaknesses", []):
        for desc in fraqueza.get("description", []):
            if desc.get("lang") == "en":
                valor = desc.get("value")

                if valor and valor not in codigos:
                    codigos.append(valor)

    return ", ".join(codigos) if codigos else None


def gerar(caminho: Path):
    if caminho.suffix == ".csv":
        df = pd.read_csv(caminho, comment="#")
        perfil = ProfileReport(df, title=caminho.name)

    elif caminho.suffix == ".json":
        with caminho.open("r", encoding="utf-8") as f:
            dados_brutos = json.load(f)

        registros = []

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
        perfil = ProfileReport(
            df,
            title=caminho.name,
            minimal=False,
        )

    else:
        raise ValueError(
            f"Extensão não suportada: {caminho.suffix}"
        )

    RELATORIOS.mkdir(exist_ok=True)

    saida = RELATORIOS / f"{caminho.stem}.html"
    perfil.to_file(saida)

    return saida


def main():
    for pasta, padrao in FONTES_CSV + FONTES_NVD:
        caminho = utils.mais_recente(pasta, padrao)

        print(f"Perfilando: {caminho.name}")

        arquivo_relatorio = gerar(caminho)

        print(
            f"Relatório gerado em: {arquivo_relatorio}\n"
        )


if __name__ == "__main__":
    main()