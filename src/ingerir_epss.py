import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

import requests

BRONZE = Path("dados/bronze/epss")
URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def baixar():
    print("Baixando arquivo diário do EPSS...")
    resposta = requests.get(URL, timeout=60)
    resposta.raise_for_status()

    conteudo_compactado = resposta.content
    conteudo_descompactado = gzip.decompress(conteudo_compactado)

    return conteudo_descompactado


def salvar(dados):
    BRONZE.mkdir(parents=True, exist_ok=True)

    hoje = datetime.now(timezone.utc).astimezone().date().strftime("%Y%m%d")
    destino = BRONZE / f"epss_{hoje}.csv"

    with destino.open("wb") as arquivo:
        arquivo.write(dados)

    print(f"Arquivo salvo em: {destino}")

    return destino


def registrar(destino):
    info = {
        "fonte": URL,
        "arquivo_bronze": destino.name,
        "extraido_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
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
