import json
from datetime import datetime, timezone
from config import BRONZE_CISA_KEV as BRONZE, configurar_log


import requests
import logging

URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
log = logging.getLogger(__name__)


def baixar():
    log.info("Baixando catalogo CISA KEV...")
    resposta = requests.get(URL, timeout=60)
    resposta.raise_for_status()

    conteudo = resposta.content

    return conteudo


def salvar(dados):
    BRONZE.mkdir(parents=True, exist_ok=True)

    hoje = datetime.now(timezone.utc).astimezone().date().strftime("%Y%m%d")
    destino = BRONZE / f"cisa_kev_{hoje}.csv"

    with destino.open("wb") as arquivo:
        arquivo.write(dados)

    log.info("Arquivo salvo em: %s", destino)

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
    configurar_log()
    main()
