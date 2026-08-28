from pathlib import Path
from datetime import date, datetime
import gzip
import json

import requests

BRONZE = Path("dados/bronze/epss")
URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def baixar():
    resposta = requests.get(URL, timeout=30)
    resposta.raise_for_status()

    conteudo_compactado = resposta.content
    conteudo_descompactado = gzip.decompress(conteudo_compactado)

    return conteudo_descompactado


def salvar(dados):
    BRONZE.mkdir(parents=True, exist_ok=True)

    hoje = date.today().strftime("%Y%m%d")
    destino = BRONZE / f"epss_{hoje}.csv"

    with destino.open("wb") as arquivo:
        arquivo.write(dados)

    print(f"Arquivo salvo em: {destino}")

    return destino


def registrar(destino):
    info = {
        "fonte": URL,
        "arquivo_bronze": destino.name,
        "extraido_em": datetime.now().isoformat(),
    }

    caminho = BRONZE / "proveniencia.jsonl"

    with caminho.open("a", encoding="utf-8") as arquivo:
        arquivo.write(json.dumps(info, ensure_ascii=False) + "\n")


def main():
    conteudo = baixar()
    destino = salvar(conteudo)
    registrar(destino)


if __name__ == "__main__":
    main()
