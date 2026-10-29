#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analizador de mensajes sospechosos (phishing y estafas por WhatsApp, SMS o mail).

Solo biblioteca estándar. Las reglas viven en reglas.json y las comparte con la
versión JavaScript (web/analizador.js): los dos motores dan el mismo resultado,
y eso se verifica en tests/test_paridad.py.

Uso:
    python analyzer.py -t "texto sospechoso"
    python analyzer.py mensaje.txt
    cat mensaje.txt | python analyzer.py --json

Códigos de salida:
    0  sin señales claras
    1  sospechoso
    2  muy probablemente estafa
    64 error de uso
    66 no se pudo leer la entrada
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["Analizador", "analizar", "cargar_reglas", "normalizar", "LIMITE_CARACTERES"]

LIMITE_CARACTERES = 5000
RUTA_REGLAS = Path(__file__).resolve().with_name("reglas.json")
CODIGOS_SALIDA = {"bajo": 0, "medio": 1, "alto": 2}
EX_USAGE = 64
EX_NOINPUT = 66

# Todas las expresiones usan re.ASCII para comportarse igual que JavaScript.
_ESPACIOS = re.compile(r"[ \t\r\n\f\v\u00a0\u2028\u2029\u3000]+")
_RE_EXPLICITO = re.compile(r"(?:https?://|www\.)[^ ]+", re.ASCII)
_RE_DOMINIO = re.compile(r"^(?:[a-z0-9-]+\.)+([a-z]{2,24})(?::[0-9]+)?(?:[/?#].*)?$", re.ASCII)
_RE_IP = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?::[0-9]+)?(?:[/?#].*)?$", re.ASCII)
_RE_IP_HOST = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$", re.ASCII)
_RE_ESQUEMA = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.ASCII)
_RE_HASTA_BARRA = re.compile(r"^[^/?#]*")
_RE_PUERTO = re.compile(r":[0-9]*$")
_INICIO = "([<\"'\u00a1\u00bf"
_FIN = ".,;:!?)]>\"'"


def cargar_reglas(ruta: Optional[Path] = None) -> Dict[str, Any]:
    """Lee y valida las reglas (por defecto, reglas.json junto a este archivo)."""
    ruta = Path(ruta) if ruta else RUTA_REGLAS
    with open(ruta, encoding="utf-8") as f:
        reglas = json.load(f)
    for clave in ("niveles", "senales_texto", "senales_enlace", "entidades", "acortadores",
                  "tld_sospechosos", "tlds_reconocidos", "sufijos_dobles",
                  "patron_banco_generico", "consejos"):
        if clave not in reglas:
            raise ValueError("reglas invalidas: falta la clave '%s'" % clave)
    return reglas


def normalizar(texto: str) -> str:
    """Minúsculas, sin tildes y con los espacios colapsados."""
    t = unicodedata.normalize("NFD", texto.lower())
    t = "".join(c for c in t if not "\u0300" <= c <= "\u036f")
    return _ESPACIOS.sub(" ", t).strip(" ")


def _limpiar(token: str) -> str:
    return token.lstrip(_INICIO).rstrip(_FIN)


def extraer_host(url: str) -> str:
    u = _RE_ESQUEMA.sub("", url)
    u = _RE_HASTA_BARRA.match(u).group(0)
    if "@" in u:
        u = u.rsplit("@", 1)[1]
    u = _RE_PUERTO.sub("", u)
    return u.strip(".")


def _recortar(s: str, maximo: int = 60) -> str:
    return s if len(s) <= maximo else s[: maximo - 3] + "..."


class Analizador:
    """Motor de análisis. Se crea una vez con las reglas y se reutiliza."""

    def __init__(self, reglas: Optional[Dict[str, Any]] = None) -> None:
        self.reglas = reglas if reglas is not None else cargar_reglas()
        r = self.reglas
        self._texto = [(s, [re.compile(p, re.ASCII) for p in s["patrones"]])
                       for s in r["senales_texto"]]
        self._entidades = [(e, [re.compile(p, re.ASCII) for p in e["menciones"]])
                           for e in r["entidades"]]
        self._banco = re.compile(r["patron_banco_generico"], re.ASCII)
        self._niveles = sorted(r["niveles"], key=lambda n: n["min"])
        self._sufijos = set(r["sufijos_dobles"])
        self._tlds = set(r["tlds_reconocidos"])
        self._tld_raros = set(r["tld_sospechosos"])

    # -- enlaces ---------------------------------------------------------------

    def _es_dominio(self, candidato: str) -> bool:
        m = _RE_DOMINIO.match(candidato)
        return bool(m) and m.group(1) in self._tlds

    @staticmethod
    def _es_ip_publica(candidato: str) -> bool:
        """IP suelta (sin http://) que vale como enlace: octetos validos y no privada."""
        host = extraer_host(candidato)
        if not _RE_IP_HOST.match(host):
            return False
        a, b, _, _ = [int(x) for x in host.split(".")]
        if any(int(x) > 255 for x in host.split(".")):
            return False
        privada = (a in (0, 10, 127) or (a == 172 and 16 <= b <= 31)
                   or (a == 192 and b == 168) or (a == 169 and b == 254))
        return not privada

    def _separar_enlaces(self, norm: str) -> Tuple[List[Dict[str, str]], str]:
        """Devuelve los enlaces encontrados y el texto sin ellos."""
        enlaces: List[Dict[str, str]] = []
        resto: List[str] = []
        for tok in norm.split(" "):
            limpio = _limpiar(tok)
            enlace = None
            m = _RE_EXPLICITO.search(tok)
            if m:
                enlace = _limpiar(m.group(0))
            elif limpio and "@" not in limpio and ((_RE_IP.match(limpio) and self._es_ip_publica(limpio))
                                                  or self._es_dominio(limpio)):
                enlace = limpio
            if enlace:
                host = extraer_host(enlace)
                if host:
                    enlaces.append({"url": enlace, "host": host})
                    continue
            resto.append(tok)
        return enlaces, " ".join(resto)

    def _es_oficial(self, host: str, ent: Dict[str, Any]) -> bool:
        for d in ent["oficiales"]:
            if host == d or host.endswith("." + d):
                return True
        if ent.get("gubernamental") and (host == "gob.ar" or host.endswith(".gob.ar")):
            return True
        return False

    def _senales_de_host(self, host: str) -> List[str]:
        ids: List[str] = []
        etiquetas = host.split(".")
        es_ip = bool(_RE_IP_HOST.match(host))

        if es_ip:
            ids.append("ip_directa")
        if any(e.startswith("xn--") for e in etiquetas) or any(ord(c) > 127 for c in host):
            ids.append("punycode")
        for a in self.reglas["acortadores"]:
            if host == a or host.endswith("." + a):
                ids.append("acortador")
                break
        if not es_ip and len(etiquetas) >= 2 and etiquetas[-1] in self._tld_raros:
            ids.append("tld_raro")

        if len(etiquetas) >= 3 and ".".join(etiquetas[-2:]) in self._sufijos:
            registro = etiquetas[-3]
        elif len(etiquetas) >= 2:
            registro = etiquetas[-2]
        else:
            registro = etiquetas[0]
        if registro.count("-") >= 2:
            ids.append("muchos_guiones")

        sin_guiones = host.replace("-", "")
        partes = set(re.split(r"[.\-]", host))
        for ent in self.reglas["entidades"]:
            if self._es_oficial(host, ent):
                continue
            if any(t in partes for t in ent["tokens"]) or any(s in sin_guiones for s in ent["subcadenas"]):
                ids.append("imita_marca")
                break
        return ids

    # -- análisis --------------------------------------------------------------

    def analizar(self, texto: str) -> Dict[str, Any]:
        texto = texto if isinstance(texto, str) else ""
        truncado = len(texto) > LIMITE_CARACTERES
        norm = normalizar(texto[:LIMITE_CARACTERES])
        enlaces, sin_enlaces = self._separar_enlaces(norm)

        senales: List[Dict[str, Any]] = []

        def agregar(regla: Dict[str, Any], tipo: str, evidencia: List[str]) -> None:
            senales.append({
                "id": regla["id"], "tipo": tipo, "etiqueta": regla["etiqueta"],
                "detalle": regla["detalle"], "peso": regla["peso"], "evidencia": evidencia,
            })

        for regla, patrones in self._texto:
            for p in patrones:
                m = p.search(sin_enlaces)
                if m:
                    agregar(regla, "texto", [_recortar(m.group(0))])
                    break

        acum: Dict[str, List[str]] = {}

        def marcar(id_: str, evidencia: str) -> None:
            lista = acum.setdefault(id_, [])
            if evidencia not in lista:
                lista.append(evidencia)

        for e in enlaces:
            for id_ in self._senales_de_host(e["host"]):
                marcar(id_, e["host"])
        for ent, patrones in self._entidades:
            if enlaces and any(p.search(sin_enlaces) for p in patrones):
                if not any(self._es_oficial(e["host"], ent) for e in enlaces):
                    marcar("dice_ser_entidad", ent["nombre"])
        if enlaces:
            m = self._banco.search(sin_enlaces)
            if m:
                marcar("banco_con_link", m.group(0))

        for regla in self.reglas["senales_enlace"]:
            if regla["id"] in acum:
                agregar(regla, "enlace", acum[regla["id"]][:3])

        puntaje = min(100, sum(s["peso"] for s in senales))
        nivel = self._niveles[0]
        for n in self._niveles:
            if puntaje >= n["min"]:
                nivel = n
        consejos = list(self.reglas["consejos"]) if nivel["id"] != "bajo" else []
        return {
            "puntaje": puntaje,
            "nivel": {"id": nivel["id"], "etiqueta": nivel["etiqueta"], "resumen": nivel["resumen"]},
            "senales": senales,
            "enlaces": enlaces,
            "consejos": consejos,
            "truncado": truncado,
        }


_por_defecto: Optional[Analizador] = None


def analizar(texto: str) -> Dict[str, Any]:
    """Atajo: analiza con las reglas por defecto."""
    global _por_defecto
    if _por_defecto is None:
        _por_defecto = Analizador()
    return _por_defecto.analizar(texto)


# -- línea de comandos ---------------------------------------------------------


def formatear(res: Dict[str, Any]) -> str:
    n = res["nivel"]
    out = ["Resultado: %s  (puntaje %d/100)" % (n["etiqueta"].upper(), res["puntaje"]),
           textwrap.fill(n["resumen"], 78)]
    if res["truncado"]:
        out.append("(El texto era muy largo: se analizaron los primeros %d caracteres.)" % LIMITE_CARACTERES)
    if res["senales"]:
        out += ["", "Señales encontradas:"]
        for s in res["senales"]:
            out.append("  [+%d] %s" % (s["peso"], s["etiqueta"]))
            out.append(textwrap.fill(s["detalle"], 78, initial_indent="        ", subsequent_indent="        "))
            if s["evidencia"]:
                out.append("        Detectado: " + ", ".join('"%s"' % e for e in s["evidencia"]))
    if res["enlaces"]:
        out += ["", "Enlaces detectados:"]
        out += ["  - %s" % e["url"] for e in res["enlaces"]]
    if res["consejos"]:
        out += ["", "Qué hacer:"]
        out += [textwrap.fill(c, 78, initial_indent="  %d. " % i, subsequent_indent="     ")
                for i, c in enumerate(res["consejos"], 1)]
    return "\n".join(out)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # 64 en vez del 2 de argparse (2 = "estafa")
        self.print_usage(sys.stderr)
        self.exit(EX_USAGE, "%s: error: %s\n" % (self.prog, message))


def _armar_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="analyzer.py", description="Analiza un mensaje sospechoso y lista las señales de estafa.")
    p.add_argument("archivo", nargs="?", help="archivo de texto con el mensaje ('-' = entrada estándar)")
    p.add_argument("-t", "--texto", help="mensaje a analizar, directamente en la línea de comandos")
    p.add_argument("--json", action="store_true", help="salida en JSON")
    p.add_argument("--reglas", help="ruta a un reglas.json alternativo")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    for flujo in (sys.stdout, sys.stdin):
        try:
            flujo.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    args = _armar_parser().parse_args(argv)

    try:
        if args.texto is not None:
            texto = args.texto
        elif args.archivo and args.archivo != "-":
            texto = Path(args.archivo).read_text(encoding="utf-8", errors="replace")
        elif args.archivo == "-" or not sys.stdin.isatty():
            texto = sys.stdin.read()
        else:
            _armar_parser().error("indicá un archivo, --texto o pasá el mensaje por la entrada estándar")
            return EX_USAGE
        motor = Analizador(cargar_reglas(args.reglas) if args.reglas else None)
    except (OSError, ValueError) as e:
        sys.stderr.write("No se pudo leer la entrada o las reglas: %s\n" % e)
        return EX_NOINPUT

    if not texto.strip():
        sys.stderr.write("El mensaje está vacío.\n")
        return EX_USAGE

    res = motor.analizar(texto)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(formatear(res))
    return CODIGOS_SALIDA[res["nivel"]["id"]]


if __name__ == "__main__":
    sys.exit(main())
