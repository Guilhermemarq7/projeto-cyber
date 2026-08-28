from pathlib import Path
from datetime import date, datetime
import gzip
import json
import requests

BRONZE = Path("dados/bronze/nvd")
URL_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
ANOS = [2024, 2025, 2026]


def baixar(ano: int):
    print(f"Baixando feed NVD {ano}...")
    url = f"{URL_BASE}{ano}.json.gz"

    resposta = requests.get(url, timeout=60)
    resposta.raise_for_status()

    conteudo_compactado = resposta.content
    conteudo_descompactado = gzip.decompress(conteudo_compactado)

    return conteudo_descompactado, url


def salvar(ano: int, dados):
    BRONZE.mkdir(parents=True, exist_ok=True)

    hoje = date.today().strftime("%Y%m%d")
    destino = BRONZE / f"nvd_{ano}_{hoje}.json"

    with destino.open("wb") as arquivo:
        arquivo.write(dados)

    print(f"Arquivo salvo em: {destino}")

    return destino


def registrar(url, destino):
    info = {
        "fonte": url,
        "arquivo_bronze": destino.name,
        "extraido_em": datetime.now().isoformat(),
    }

    caminho = BRONZE / "proveniencia.jsonl"

    with caminho.open("a", encoding="utf-8") as arquivo:
        arquivo.write(json.dumps(info, ensure_ascii=False) + "\n")


def main():
    for ano in ANOS:
        conteudo, url = baixar(ano)
        destino = salvar(ano, conteudo)
        registrar(url, destino)


if __name__ == "__main__":
    main()
