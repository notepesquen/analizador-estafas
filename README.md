# analizador-estafas

Rule-based scam / phishing message analyzer. Paste a suspicious WhatsApp, SMS or email text and it lists the warning signs it finds (urgency, credential requests, shortened or look-alike links, impersonated institutions) with a 0–100 score.

Built for [No te pesquen](https://www.notepesquen.com.ar), a free Spanish-language course that teaches non-technical adults to spot online scams. Rules target Argentine scams (ANSES, ARCA, Correo Argentino, Mercado Pago, banks), but the engine is generic.

- **Python engine + CLI**: standard library only, Python 3.8+.
- **JavaScript port** (ES5, runs client-side on old phones): used live on the course site, no data leaves the browser.
- **One shared rule file** (`reglas.json`) drives both engines. A test asserts that Python and JavaScript return identical results.

## Usage

```bash
python analyzer.py -t "Detectamos acceso sospechoso. Ingresá tu clave en bit.ly/banco-seguro"
python analyzer.py mensaje.txt
cat mensaje.txt | python analyzer.py --json
```

Exit codes make it scriptable: `0` no clear signals, `1` suspicious, `2` very likely a scam, `64` usage error, `66` unreadable input.

```python
from analyzer import analizar
res = analizar("Su paquete está retenido. Pague $150 de arancel: correo-ar-pago.com")
res["nivel"]["id"], res["puntaje"], [s["id"] for s in res["senales"]]
```

## How it works

1. Normalize the text (lowercase, strip accents, collapse whitespace; capped at 5000 chars).
2. Extract links and remove them from the text, so URL contents don't trigger text rules.
3. Match text signals (regex lists in `reglas.json`), each counted once.
4. Analyze each link's host: shortener, raw IP, punycode, odd TLD, hyphen-stuffed domain, and look-alike of a known entity (compared against that entity's official domains; any `.gob.ar` counts as official for government bodies).
5. Cross-check: the message names an entity but no link belongs to it.
6. Sum signal weights (cap 100) and map to a level (`bajo` / `medio` / `alto`).

It is a heuristic for teaching, not a verdict: no signals does not mean a message is safe.

## Tests

```bash
python construir_web.py            # regenerate web/reglas.js after editing reglas.json
python -m unittest discover -s tests -v
```

Covers fixtures (`tests/casos.json`), rule integrity, CLI exit codes, regex performance on adversarial input, and Python/JS parity (requires Node.js; skipped if absent).

## Layout

```
reglas.json        single source of truth for all rules
analyzer.py        Python engine and CLI
construir_web.py   generates web/reglas.js from reglas.json
web/               analizador.js (engine), ui.js (page UI, no innerHTML), reglas.js (generated)
tests/             unittest suite and JS runner for parity
```

To use it on the site, copy `web/reglas.js`, `web/analizador.js` and `web/ui.js` to `analizador/` in the site repo.

## Limits

Spanish only; regex heuristics will miss novel wording and flag some legitimate messages. Weights are hand-tuned on a small fixture set. Link reputation is not checked (no network calls by design).

MIT licensed.
