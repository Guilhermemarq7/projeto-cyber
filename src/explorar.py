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


def metrica_primaria(cve: dict):
    # Prioridade de métricas CVSS conforme schema do NVD:
    # 1. cvssMetricV40 (CVSS 4.0 - mais recente e preciso)
    # 2. cvssMetricV31 (CVSS 3.1 - maior volume)
    # 3. cvssMetricV30
    # 4. cvssMetricV2
    ordem_prioridade = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

    for versao in ordem_prioridade:
        lista_metricas = cve.get("metrics", {}).get(versao, [])

        for m in lista_metricas:
            dados = m.get("cvssData", {})
            score = dados.get("baseScore")

            if versao == "cvssMetricV2":
                # Na especificação CVSS v2, 'baseSeverity' fica na raiz do objeto da métricas (m)
                severidade = m.get("baseSeverity")
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
            score, severidade, versao_cvss = metrica_primaria(cve)
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