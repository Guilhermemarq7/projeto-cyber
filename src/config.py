
"""Configuracoes compartilhadas do Projeto Cyber."""


import logging
import sys
from pathlib import Path


# Raiz do repositorio, independente de onde o terminal estiver aberto.
RAIZ = Path(__file__).resolve().parent.parent

# Camadas da arquitetura medalhao.
DADOS = RAIZ / "dados"
BRONZE = DADOS / "bronze"
PRATA = DADOS / "prata"
OURO = DADOS / "ouro"

# Diretorio dos relatorios de exploracao.
RELATORIOS = RAIZ / "relatorios"

# Diretorios das fontes na Bronze.
BRONZE_NVD = BRONZE / "nvd"
BRONZE_EPSS = BRONZE / "epss"
BRONZE_CISA_KEV = BRONZE / "cisa_kev"

# Anos dos identificadores CVE utilizados no recorte NVD.
ANOS_NVD = [2024, 2025, 2026]


# Arquivo de log das execucoes do projeto.
ARQUIVO_LOG = RAIZ / "pipeline.log"


def configurar_log():
    """Configura mensagens no terminal e no arquivo pipeline.log."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(ARQUIVO_LOG, encoding="utf-8"),
        ],
        force=True,
    )