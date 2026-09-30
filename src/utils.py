"""Funcoes utilitarias gerais do projeto.

Diferente de limpeza.py, aqui NAO entra nada que trate/corrija dado --
sao funcoes de infraestrutura (achar arquivo, registrar proveniencia)
que qualquer script do projeto pode precisar, tenha ou nao limpeza.
"""
from pathlib import Path
from datetime import datetime
import json


def mais_recente(pasta: Path, padrao: str) -> Path:
    arquivos = sorted(pasta.glob(padrao))
    if not arquivos:
        raise FileNotFoundError(
            f"Nenhum arquivo encontrado em '{pasta}' com o padrão '{padrao}'"
        )
    return arquivos[-1]


def registrar(pasta_prata: Path, origem, destino, antes, depois, decisoes):
    """Grava uma linha em <pasta_prata>/proveniencia.jsonl.

    'origem' aceita um Path (caso comum: um arquivo bronze) ou uma
    lista/string já pronta (caso do NVD, que junta 3 arquivos numa
    lista de nomes)."""
    origem_registrada = origem.name if isinstance(origem, Path) else origem

    info = {
        "origem": origem_registrada,
        "arquivo_prata": destino.name,
        "linhas_antes": antes,
        "linhas_depois": depois,
        "decisoes": decisoes,
        "transformado_em": datetime.now().isoformat(timespec="seconds"),
    }
    caminho = pasta_prata / "proveniencia.jsonl"
    with caminho.open("a", encoding="utf-8") as f:
        f.write(json.dumps(info, ensure_ascii=False) + "\n")
