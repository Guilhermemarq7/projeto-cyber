import json
from pathlib import Path

import pandas as pd
from data_profiling import ProfileReport

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

# Politica LOCAL do projeto para escolher uma unica versao CVSS.
# Esta ordem nao representa uma precedencia oficial do NVD.
ORDEM_CVSS = (
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2",
)

def mais_recente(pasta: Path, padrao: str) -> Path:
    arquivos = sorted(pasta.glob(padrao))
    if not arquivos:
        raise FileNotFoundError(
            f"Nenhum arquivo encontrado em '{pasta}' com o padrão '{padrao}'"
        )
    return arquivos[-1]


def descricao_en(cve: dict):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value")
    return None


def selecionar_metrica_cvss(cve: dict):
    """Seleciona uma metrica CVSS pela politica local do projeto.

    A politica prefere a versao mais nova disponivel e, dentro dela,
    utiliza a primeira metrica que possui baseScore.

    Essa ordem e uma decisao do projeto, nao uma precedencia oficial do NVD.
    """
    metricas = cve.get("metrics", {})

    for versao in ORDEM_CVSS:
        lista_metricas = metricas.get(versao, [])

        for metrica in lista_metricas:
            dados = metrica.get("cvssData", {})
            score = dados.get("baseScore")

            if score is None:
                continue

            if versao == "cvssMetricV2":
                severidade = metrica.get("baseSeverity")
            else:
                severidade = dados.get("baseSeverity")

            return score, severidade, versao

    return None, None, None


def cwes(cve: dict):
    # Extrai os identificadores CWE (ex.: "CWE-79, CWE-89") para padronização com a base CISA KEV
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
            score, severidade, versao_cvss = selecionar_metrica_cvss(cve)
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
                "num_referencias": len(cve.get("references", [])),
                "num_fraquezas": len(cve.get("weaknesses", [])),
                "cwes": cwes(cve),
            })

        df = pd.DataFrame(registros)

        # Gera profiling completo sobre os dados estruturados
        perfil = ProfileReport(df, title=caminho.name, minimal=False)

    else:
        raise ValueError(f"Extensão não suportada: {caminho.suffix}")

    RELATORIOS.mkdir(exist_ok=True)
    saida = RELATORIOS / f"{caminho.stem}.html"
    perfil.to_file(saida)

    return saida


def main():
    for pasta, padrao in FONTES_CSV + FONTES_NVD:
        caminho = mais_recente(pasta, padrao)
        print(f"Perfilando: {caminho.name}")
        arquivo_relatorio = gerar(caminho)
        print(f"Relatório gerado em: {arquivo_relatorio}\n")


if __name__ == "__main__":
    main()