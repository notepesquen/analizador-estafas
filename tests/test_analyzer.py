"""Tests del motor Python. Ejecutar con:  python -m unittest discover -s tests -v"""
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

import analyzer  # noqa: E402

CASOS = json.loads((Path(__file__).parent / "casos.json").read_text(encoding="utf-8"))


class TestCasos(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.motor = analyzer.Analizador()

    def test_casos(self):
        for caso in CASOS:
            with self.subTest(caso=caso["id"]):
                res = self.motor.analizar(caso["texto"])
                ids = {s["id"] for s in res["senales"]}
                self.assertEqual(res["nivel"]["id"], caso["nivel"], "puntaje=%d, senales=%s" % (res["puntaje"], sorted(ids)))
                if "puntaje" in caso:
                    self.assertEqual(res["puntaje"], caso["puntaje"])
                for esperado in caso.get("contiene", []):
                    self.assertIn(esperado, ids)
                for prohibido in caso.get("no_contiene", []):
                    self.assertNotIn(prohibido, ids)


class TestPiezas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.motor = analyzer.Analizador()

    def test_normalizar(self):
        self.assertEqual(analyzer.normalizar("  ¡Hacé   CLIC\n aquí, Ñandú!  "), "¡hace clic aqui, nandu!")

    def test_extraer_host(self):
        casos = {
            "https://user:pw@Sitio.com:8080/a?b=c": "sitio.com".replace("s", "s"),
            "www.ejemplo.com.ar/ruta": "www.ejemplo.com.ar",
            "bit.ly/abc": "bit.ly",
            "http://190.1.2.3:81/x": "190.1.2.3",
        }
        # extraer_host trabaja sobre texto ya normalizado (minúsculas)
        for url, esperado in casos.items():
            self.assertEqual(analyzer.extraer_host(url.lower()), esperado)

    def test_enlaces_detectados(self):
        res = self.motor.analizar("Mirá https://a.com/x, www.b.com.ar y c.xyz/p. También d.pdf y 3.5 no.")
        self.assertEqual([e["host"] for e in res["enlaces"]], ["a.com", "www.b.com.ar", "c.xyz"])

    def test_gubernamental_cualquier_gob_ar(self):
        res = self.motor.analizar("ANSES informa novedades en https://www.argentina.gob.ar/anses")
        ids = {s["id"] for s in res["senales"]}
        self.assertNotIn("dice_ser_entidad", ids)

    def test_gob_ar_falso_como_subdominio_ajeno(self):
        res = self.motor.analizar("ANSES: ingresá a anses.gob.ar.cobros-ya.com")
        ids = {s["id"] for s in res["senales"]}
        self.assertIn("dice_ser_entidad", ids)
        self.assertIn("imita_marca", ids)

    def test_puntaje_tope_100(self):
        texto = "URGENTE acceso sospechoso. Ingresá tu clave en http://1.2.3.4 bit.ly/x ganaste un premio"
        self.assertEqual(self.motor.analizar(texto)["puntaje"], 100)

    def test_truncado(self):
        res = self.motor.analizar("a" * (analyzer.LIMITE_CARACTERES + 1))
        self.assertTrue(res["truncado"])

    def test_entrada_no_texto(self):
        self.assertEqual(self.motor.analizar(None)["puntaje"], 0)  # type: ignore[arg-type]

    def test_regex_pesadas_terminan_rapido(self):
        import time
        inicio = time.time()
        self.motor.analizar(("paquete " * 600) + ("a-" * 1000) + ("http://" * 300))
        self.assertLess(time.time() - inicio, 2.0)


class TestReglas(unittest.TestCase):
    def setUp(self):
        self.reglas = analyzer.cargar_reglas()

    def test_ids_unicos(self):
        ids = [s["id"] for s in self.reglas["senales_texto"] + self.reglas["senales_enlace"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_patrones_compilan_y_estan_normalizados(self):
        patrones = [p for s in self.reglas["senales_texto"] for p in s["patrones"]]
        patrones += [p for e in self.reglas["entidades"] for p in e["menciones"]]
        for p in patrones:
            re.compile(p)
            self.assertEqual(p, p.lower(), "el patrón debe estar en minúsculas: " + p)
            self.assertFalse(re.search(r"[^\x00-\x7f]", p), "el patrón debe ser ASCII (sin tildes): " + p)

    def test_niveles(self):
        mins = [n["min"] for n in self.reglas["niveles"]]
        self.assertEqual(mins[0], 0)
        self.assertEqual(mins, sorted(mins))

    def test_pesos_positivos(self):
        for s in self.reglas["senales_texto"] + self.reglas["senales_enlace"]:
            self.assertGreater(s["peso"], 0)

    def test_senales_de_enlace_todas_implementadas(self):
        # cada id de enlace debe poder dispararse con algún texto de prueba
        pruebas = {
            "acortador": "bit.ly/x", "ip_directa": "http://1.2.3.4/x", "punycode": "http://xn--a.com",
            "imita_marca": "galicia-pagos.com", "dice_ser_entidad": "Banco Galicia: entrá a hola.com",
            "tld_raro": "hola.xyz", "muchos_guiones": "a-b-c.com", "banco_con_link": "tu banco: hola.com",
        }
        motor = analyzer.Analizador(self.reglas)
        for regla in self.reglas["senales_enlace"]:
            ids = {s["id"] for s in motor.analizar(pruebas[regla["id"]])["senales"]}
            self.assertIn(regla["id"], ids)


class TestCLI(unittest.TestCase):
    def correr(self, *args, entrada=None):
        return subprocess.run([sys.executable, "-I", str(RAIZ / "analyzer.py"), *args], input=entrada,
                              capture_output=True, text=True, encoding="utf-8")

    def test_codigos_de_salida(self):
        self.assertEqual(self.correr("-t", "Hola, nos vemos mañana").returncode, 0)
        self.assertEqual(self.correr("-t", "Mirá las fotos, hacé clic acá").returncode, 1)
        self.assertEqual(self.correr("-t", "acceso sospechoso: ingresá tu clave en bit.ly/x").returncode, 2)

    def test_json(self):
        r = self.correr("--json", "-", entrada="Hacé clic aquí urgente")
        data = json.loads(r.stdout)
        self.assertIn("puntaje", data)
        self.assertEqual(data["nivel"]["id"], "medio")

    def test_archivo_inexistente(self):
        self.assertEqual(self.correr("no_existe.txt").returncode, 66)

    def test_uso_incorrecto(self):
        self.assertEqual(self.correr("--no-existe").returncode, 64)
        self.assertEqual(self.correr("-t", "   ").returncode, 64)

    def test_salida_legible(self):
        r = self.correr("-t", "Tu cuenta será bloqueada. Hacé clic aquí")
        self.assertIn("Señales encontradas", r.stdout)
        self.assertIn("Qué hacer", r.stdout)


if __name__ == "__main__":
    unittest.main()
