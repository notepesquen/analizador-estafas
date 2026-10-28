/*
 * Analizador de mensajes sospechosos - port en JavaScript (ES5) de analyzer.py.
 * Sin dependencias. Funciona en celulares viejos (sin flechas, let/const ni fetch).
 * Las reglas salen de reglas.json (en el navegador, via reglas.js -> window.REGLAS_ESTAFAS).
 * Que el resultado sea identico al de Python se verifica en tests/test_paridad.py.
 */
(function (raiz, fabrica) {
  var api = fabrica();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    raiz.AnalizadorEstafas = api;
  }
})(typeof window !== "undefined" ? window : this, function () {
  "use strict";

  var LIMITE_CARACTERES = 5000;
  var RE_ESPACIOS = /[ \t\r\n\f\v\u00a0\u2028\u2029\u3000]+/g;
  var RE_EXPLICITO = /(?:https?:\/\/|www\.)[^ ]+/;
  var RE_DOMINIO = /^(?:[a-z0-9-]+\.)+([a-z]{2,24})(?::[0-9]+)?(?:[\/?#].*)?$/;
  var RE_IP = /^[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?::[0-9]+)?(?:[\/?#].*)?$/;
  var RE_IP_HOST = /^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$/;
  var RE_ESQUEMA = /^[a-z][a-z0-9+.\-]*:\/\//;
  var RE_HASTA_BARRA = /^[^\/?#]*/;
  var RE_PUERTO = /:[0-9]*$/;
  var INICIO = "([<\"'\u00a1\u00bf";
  var FIN = ".,;:!?)]>\"'";

  // Respaldo para navegadores sin String.prototype.normalize (iOS 9 y anteriores).
  var TABLA = {
    "\u00e1": "a", "\u00e0": "a", "\u00e4": "a", "\u00e2": "a", "\u00e3": "a",
    "\u00e9": "e", "\u00e8": "e", "\u00eb": "e", "\u00ea": "e",
    "\u00ed": "i", "\u00ec": "i", "\u00ef": "i", "\u00ee": "i",
    "\u00f3": "o", "\u00f2": "o", "\u00f6": "o", "\u00f4": "o", "\u00f5": "o",
    "\u00fa": "u", "\u00f9": "u", "\u00fc": "u", "\u00fb": "u",
    "\u00f1": "n", "\u00e7": "c"
  };

  function sinTildes(t) {
    if (typeof t.normalize === "function") {
      return t.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
    }
    return t.replace(/[\u00e0-\u00f6\u00f8-\u00fc]/g, function (c) { return TABLA[c] || c; });
  }

  function normalizar(texto) {
    return sinTildes(texto.toLowerCase()).replace(RE_ESPACIOS, " ").replace(/^ +| +$/g, "");
  }

  function limpiar(tok) {
    var i = 0, j = tok.length;
    while (i < j && INICIO.indexOf(tok.charAt(i)) !== -1) { i++; }
    while (j > i && FIN.indexOf(tok.charAt(j - 1)) !== -1) { j--; }
    return tok.substring(i, j);
  }

  function extraerHost(url) {
    var u = url.replace(RE_ESQUEMA, "");
    u = u.match(RE_HASTA_BARRA)[0];
    var arroba = u.lastIndexOf("@");
    if (arroba !== -1) { u = u.substring(arroba + 1); }
    u = u.replace(RE_PUERTO, "");
    return u.replace(/^\.+|\.+$/g, "");
  }

  function recortar(s) {
    return s.length <= 60 ? s : s.substring(0, 57) + "...";
  }

  function terminaEn(s, fin) {
    return s.length >= fin.length && s.substring(s.length - fin.length) === fin;
  }

  function contiene(lista, valor) {
    return lista.indexOf(valor) !== -1;
  }

  function compilarLista(patrones) {
    var out = [];
    for (var i = 0; i < patrones.length; i++) { out.push(new RegExp(patrones[i])); }
    return out;
  }

  function crear(reglas) {
    var i;
    var texto = [];
    for (i = 0; i < reglas.senales_texto.length; i++) {
      texto.push({ regla: reglas.senales_texto[i], pats: compilarLista(reglas.senales_texto[i].patrones) });
    }
    var entidades = [];
    for (i = 0; i < reglas.entidades.length; i++) {
      entidades.push({ ent: reglas.entidades[i], pats: compilarLista(reglas.entidades[i].menciones) });
    }
    var banco = new RegExp(reglas.patron_banco_generico);
    var niveles = reglas.niveles.slice().sort(function (a, b) { return a.min - b.min; });

    function esDominio(candidato) {
      var m = RE_DOMINIO.exec(candidato);
      return !!m && contiene(reglas.tlds_reconocidos, m[1]);
    }

    function esOficial(host, ent) {
      for (var k = 0; k < ent.oficiales.length; k++) {
        var d = ent.oficiales[k];
        if (host === d || terminaEn(host, "." + d)) { return true; }
      }
      return !!ent.gubernamental && (host === "gob.ar" || terminaEn(host, ".gob.ar"));
    }

    function separarEnlaces(norm) {
      var enlaces = [], resto = [], toks = norm.split(" ");
      for (var k = 0; k < toks.length; k++) {
        var tok = toks[k];
        var limpio = limpiar(tok);
        var enlace = null;
        var m = RE_EXPLICITO.exec(tok);
        if (m) {
          enlace = limpiar(m[0]);
        } else if (limpio && limpio.indexOf("@") === -1 && (RE_IP.test(limpio) || esDominio(limpio))) {
          enlace = limpio;
        }
        if (enlace) {
          var host = extraerHost(enlace);
          if (host) {
            enlaces.push({ url: enlace, host: host });
            continue;
          }
        }
        resto.push(tok);
      }
      return { enlaces: enlaces, sinEnlaces: resto.join(" ") };
    }

    function senalesDeHost(host) {
      var ids = [], k;
      var etiquetas = host.split(".");
      var esIp = RE_IP_HOST.test(host);

      if (esIp) { ids.push("ip_directa"); }
      var raro = false;
      for (k = 0; k < etiquetas.length; k++) {
        if (etiquetas[k].indexOf("xn--") === 0) { raro = true; }
      }
      for (k = 0; k < host.length; k++) {
        if (host.charCodeAt(k) > 127) { raro = true; }
      }
      if (raro) { ids.push("punycode"); }
      for (k = 0; k < reglas.acortadores.length; k++) {
        var a = reglas.acortadores[k];
        if (host === a || terminaEn(host, "." + a)) { ids.push("acortador"); break; }
      }
      if (!esIp && etiquetas.length >= 2 && contiene(reglas.tld_sospechosos, etiquetas[etiquetas.length - 1])) {
        ids.push("tld_raro");
      }

      var registro;
      if (etiquetas.length >= 3 &&
          contiene(reglas.sufijos_dobles, etiquetas.slice(-2).join("."))) {
        registro = etiquetas[etiquetas.length - 3];
      } else if (etiquetas.length >= 2) {
        registro = etiquetas[etiquetas.length - 2];
      } else {
        registro = etiquetas[0];
      }
      if (registro.split("-").length - 1 >= 2) { ids.push("muchos_guiones"); }

      var sinGuiones = host.replace(/-/g, "");
      var partes = host.split(/[.\-]/);
      for (k = 0; k < reglas.entidades.length; k++) {
        var ent = reglas.entidades[k];
        if (esOficial(host, ent)) { continue; }
        var imita = false, t;
        for (t = 0; t < ent.tokens.length; t++) {
          if (contiene(partes, ent.tokens[t])) { imita = true; }
        }
        for (t = 0; t < ent.subcadenas.length; t++) {
          if (sinGuiones.indexOf(ent.subcadenas[t]) !== -1) { imita = true; }
        }
        if (imita) { ids.push("imita_marca"); break; }
      }
      return ids;
    }

    function analizar(entrada) {
      var original = typeof entrada === "string" ? entrada : "";
      var truncado = original.length > LIMITE_CARACTERES;
      var norm = normalizar(original.substring(0, LIMITE_CARACTERES));
      var sep = separarEnlaces(norm);
      var enlaces = sep.enlaces, sinEnlaces = sep.sinEnlaces;
      var senales = [], k, p;

      function agregar(regla, tipo, evidencia) {
        senales.push({
          id: regla.id, tipo: tipo, etiqueta: regla.etiqueta,
          detalle: regla.detalle, peso: regla.peso, evidencia: evidencia
        });
      }

      for (k = 0; k < texto.length; k++) {
        for (p = 0; p < texto[k].pats.length; p++) {
          var m = texto[k].pats[p].exec(sinEnlaces);
          if (m) { agregar(texto[k].regla, "texto", [recortar(m[0])]); break; }
        }
      }

      var acum = {};
      function marcar(id, evidencia) {
        if (!acum.hasOwnProperty(id)) { acum[id] = []; }
        if (!contiene(acum[id], evidencia)) { acum[id].push(evidencia); }
      }

      for (k = 0; k < enlaces.length; k++) {
        var ids = senalesDeHost(enlaces[k].host);
        for (p = 0; p < ids.length; p++) { marcar(ids[p], enlaces[k].host); }
      }
      if (enlaces.length) {
        for (k = 0; k < entidades.length; k++) {
          var mencionada = false;
          for (p = 0; p < entidades[k].pats.length; p++) {
            if (entidades[k].pats[p].test(sinEnlaces)) { mencionada = true; break; }
          }
          if (!mencionada) { continue; }
          var hayOficial = false;
          for (p = 0; p < enlaces.length; p++) {
            if (esOficial(enlaces[p].host, entidades[k].ent)) { hayOficial = true; }
          }
          if (!hayOficial) { marcar("dice_ser_entidad", entidades[k].ent.nombre); }
        }
        var mb = banco.exec(sinEnlaces);
        if (mb) { marcar("banco_con_link", mb[0]); }
      }

      for (k = 0; k < reglas.senales_enlace.length; k++) {
        var regla = reglas.senales_enlace[k];
        if (acum.hasOwnProperty(regla.id)) { agregar(regla, "enlace", acum[regla.id].slice(0, 3)); }
      }

      var puntaje = 0;
      for (k = 0; k < senales.length; k++) { puntaje += senales[k].peso; }
      if (puntaje > 100) { puntaje = 100; }
      var nivel = niveles[0];
      for (k = 0; k < niveles.length; k++) {
        if (puntaje >= niveles[k].min) { nivel = niveles[k]; }
      }
      return {
        puntaje: puntaje,
        nivel: { id: nivel.id, etiqueta: nivel.etiqueta, resumen: nivel.resumen },
        senales: senales,
        enlaces: enlaces,
        consejos: nivel.id !== "bajo" ? reglas.consejos.slice() : [],
        truncado: truncado
      };
    }

    return { analizar: analizar, reglas: reglas };
  }

  return { crear: crear, normalizar: normalizar, LIMITE_CARACTERES: LIMITE_CARACTERES };
});
