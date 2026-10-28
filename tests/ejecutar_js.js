// Uso: node tests/ejecutar_js.js entradas.json
// Lee un arreglo de textos y escribe por stdout un arreglo con el resultado del motor JS.
"use strict";
var fs = require("fs");
var path = require("path");
var Analizador = require("../web/analizador.js");
var reglas = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "reglas.json"), "utf8"));
var motor = Analizador.crear(reglas);
var textos = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.stdout.write(JSON.stringify(textos.map(function (t) { return motor.analizar(t); })));
