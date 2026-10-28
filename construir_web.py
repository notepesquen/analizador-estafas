#!/usr/bin/env python3
"""Genera web/reglas.js a partir de reglas.json (única fuente de verdad).

El navegador carga reglas.js con un <script> común: sin fetch, sin CORS y
compatible con celulares viejos. Después de tocar reglas.json:

    python construir_web.py
"""
import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
ENTRADA = RAIZ / "reglas.json"
SALIDA = RAIZ / "web" / "reglas.js"


def generar_contenido() -> str:
    reglas = json.loads(ENTRADA.read_text(encoding="utf-8"))
    cuerpo = json.dumps(reglas, ensure_ascii=True, separators=(",", ":"))
    return (
        "/* Generado por construir_web.py desde reglas.json. No editar a mano. */\n"
        "window.REGLAS_ESTAFAS=" + cuerpo + ";\n"
    )


def main() -> int:
    SALIDA.parent.mkdir(exist_ok=True)
    SALIDA.write_text(generar_contenido(), encoding="utf-8", newline="\n")
    print("escrito", SALIDA.relative_to(RAIZ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
