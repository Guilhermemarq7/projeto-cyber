"""Aula 8/9: execucao sequencial das etapas do Projeto Cyber."""

import logging
import sys
from time import perf_counter

from config import configurar_log
import enriquecer
import ingerir_cisakev
import ingerir_epss
import ingerir_nvd
import transformar_cisakev
import transformar_epss
import transformar_nvd

log = logging.getLogger(__name__)


def ingerir_todas():
    """Atualiza os arquivos da camada Bronze das tres fontes."""
    ingerir_nvd.main()
    ingerir_epss.main()
    ingerir_cisakev.main()


def transformar_todas():
    """Transforma as tres fontes da Bronze para a Prata."""
    transformar_nvd.main()
    transformar_epss.main()
    transformar_cisakev.main()


def etapa_carga():
    """Importa apenas quando a etapa for executada."""
    import carga

    carga.main()


ETAPAS = [
    ("ingestao", ingerir_todas),
    ("transformacao", transformar_todas),
    ("enriquecimento", enriquecer.main),
    ("carga", etapa_carga),
    ("modelagem", None),
]


def executar(nome, funcao):
    """Executa uma etapa, registra o tempo e interrompe em caso de erro."""
    log.info("etapa %s: inicio", nome)
    inicio = perf_counter()

    try:
        funcao()
    except Exception:
        log.exception("etapa %s falhou", nome)
        raise

    log.info("etapa %s: fim em %.2fs", nome, perf_counter() - inicio)


def main(a_partir_de=None):
    """Executa o pipeline completo ou retoma da etapa informada."""
    configurar_log()

    nomes = [nome for nome, _ in ETAPAS]
    if a_partir_de is not None and a_partir_de not in nomes:
        raise ValueError(
            f"Etapa desconhecida: {a_partir_de}. "
            f"Etapas validas: {', '.join(nomes)}"
        )

    comecou = a_partir_de is None

    for nome, funcao in ETAPAS:
        if nome == a_partir_de:
            comecou = True

        if not comecou:
            log.info("etapa %s: pulada (anterior ao inicio solicitado)", nome)
            continue

        if funcao is None:
            log.info("etapa %s: pulada (ainda nao implementada)", nome)
            continue

        executar(nome, funcao)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        raise SystemExit(
            "Uso: python src/pipeline.py "
            "[ingestao|transformacao|enriquecimento|carga|modelagem]"
        )

    main(sys.argv[1] if len(sys.argv) == 2 else None)
