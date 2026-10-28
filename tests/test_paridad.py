"""El motor JavaScript debe dar exactamente el mismo resultado que el de Python."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

import analyzer  # noqa: E402
import construir_web  # noqa: E402

CASOS = json.loads((Path(__file__).parent / "casos.json").read_text(encoding="utf-8"))

EXTRA = [
    "WWW.BANCO-GALICIA-SEGURO.COM.AR/login?x=1 Ingrese su clave",
    "Ingresá a (https://mercadopago-ayuda.com), es urgente!!!",
    "Hola papá, este es mi nuevo número. Pasame plata por favor, no le digas a mamá",
    "Tu paquete retenido: correoargentino-envios.top/pago o se devuelve en 48 hs",
    "http://[::1]/x y ftp://servidor.com y a@b.com y 1.2.3.4:8080/ruta",
    "AFIP: regularizá tus datos en arca.com.ar o afip-pagos.net antes de 2 horas",
    "Visitá https://www.aerolineas.com.ar/ofertas y también aerolineas-gratis.click",
    "  \n\t  ",
    "ñandú ÁÉÍÓÚ Üü çÇ — texto con acentos, ¿verdad? ¡Sí!",
    "Ganaste una herencia. Necesitamos tu clave y el código que te llegó. No cortes.",
    "x" * 6000,
    "http://" + "a." * 80 + "com",
    "Mirá bit.ly/abc, tinyurl.com/zzz; cutt.ly/q; y goo.gl/m.",
]


def _nodo():
    return shutil.which("node") or shutil.which("nodejs")


class TestParidad(unittest.TestCase):
    @unittest.skipUnless(_nodo(), "Node.js no está instalado")
    def test_python_y_js_coinciden(self):
        textos = [c["texto"] for c in CASOS] + EXTRA
        with tempfile.TemporaryDirectory() as tmp:
            entrada = Path(tmp) / "entradas.json"
            entrada.write_text(json.dumps(textos), encoding="utf-8")
            r = subprocess.run([_nodo(), str(RAIZ / "tests" / "ejecutar_js.js"), str(entrada)],
                               capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(r.returncode, 0, r.stderr)
        desde_js = json.loads(r.stdout)
        motor = analyzer.Analizador()
        self.assertEqual(len(desde_js), len(textos))
        for texto, js in zip(textos, desde_js):
            with self.subTest(texto=texto[:50]):
                self.assertEqual(json.loads(json.dumps(motor.analizar(texto))), js)

    def test_reglas_js_sincronizado(self):
        actual = (RAIZ / "web" / "reglas.js").read_text(encoding="utf-8")
        self.assertEqual(actual, construir_web.generar_contenido(),
                         "web/reglas.js está desactualizado: ejecutá python construir_web.py")


if __name__ == "__main__":
    unittest.main()
