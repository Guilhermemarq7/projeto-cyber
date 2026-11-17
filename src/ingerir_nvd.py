import gzip
import json
from datetime import datetime, timezone

from config import (
    BRONZE_NVD as BRONZE,
    ANOS_NVD as ANOS,
    configurar_log,
)


import requests
import logging


URL_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
log = logging.getLogger(__name__)



def baixar(ano: int):

    log.info("Baixando feed NVD %s...", ano)
    url = f"{URL_BASE}{ano}.json.gz"

    resposta = requests.get(url, timeout=60)
    resposta.raise_for_status()

    conteudo_compactado = resposta.content
    conteudo_descompactado = gzip.decompress(conteudo_compactado)

    return conteudo_descompactado, url


def salvar(ano: int, dados):
    BRONZE.mkdir(parents=True, exist_ok=True)

    hoje = datetime.now(timezone.utc).astimezone().date().strftime("%Y%m%d")
    destino = BRONZE / f"nvd_{ano}_{hoje}.json"

    with destino.open("wb") as arquivo:
        arquivo.write(dados)


    log.info("Arquivo salvo em: %s", destino)


    return destino


def registrar(url, destino):
    info = {
        "fonte": url,
        "arquivo_bronze": destino.name,
        "extraido_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
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
    configurar_log()
    main()
