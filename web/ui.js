/*
 * Interfaz del analizador para el sitio "No te pesquen".
 * Todo se arma con createElement/textContent (nunca innerHTML): lo que pega la persona
 * se muestra como texto, no como HTML. ES5, para que ande en celulares viejos.
 * Requiere reglas.js (window.REGLAS_ESTAFAS) y analizador.js (window.AnalizadorEstafas).
 */
(function () {
  "use strict";

  var contenedor = document.getElementById("analizador-estafas");
  if (!contenedor) { return; }
  if (!window.AnalizadorEstafas || !window.REGLAS_ESTAFAS) { return; }

  var motor = window.AnalizadorEstafas.crear(window.REGLAS_ESTAFAS);
  var campo = document.getElementById("az-texto");
  var salida = document.getElementById("az-resultado");
  var ejemplos = document.getElementById("az-ejemplos");
  var btnAnalizar = document.getElementById("az-analizar");
  var btnLimpiar = document.getElementById("az-limpiar");
  if (!campo || !salida || !ejemplos || !btnAnalizar || !btnLimpiar) { return; }

  function el(etiqueta, clase, texto) {
    var e = document.createElement(etiqueta);
    if (clase) { e.className = clase; }
    if (texto !== undefined && texto !== null) { e.appendChild(document.createTextNode(texto)); }
    return e;
  }

  function vaciar(nodo) {
    while (nodo.firstChild) { nodo.removeChild(nodo.firstChild); }
  }

  function mostrarAviso(texto) {
    vaciar(salida);
    var tarjeta = el("div", "az-card az-nivel-aviso");
    tarjeta.appendChild(el("p", "az-resumen", texto));
    salida.appendChild(tarjeta);
  }

  function dibujar(res) {
    vaciar(salida);
    var tarjeta = el("div", "az-card az-nivel-" + res.nivel.id);

    var titulo = el("h4", "az-titulo", res.nivel.etiqueta + " (" + res.puntaje + "/100)");
    titulo.setAttribute("tabindex", "-1");
    tarjeta.appendChild(titulo);

    var barra = el("div", "az-barra");
    var relleno = el("span", "");
    relleno.style.width = res.puntaje + "%";
    barra.appendChild(relleno);
    barra.setAttribute("role", "presentation");
    tarjeta.appendChild(barra);

    tarjeta.appendChild(el("p", "az-resumen", res.nivel.resumen));
    if (res.truncado) {
      tarjeta.appendChild(el("p", "az-resumen", "El mensaje era muy largo: se analizaron los primeros " +
        window.AnalizadorEstafas.LIMITE_CARACTERES + " caracteres."));
    }

    var i, j, li;
    if (res.senales.length) {
      tarjeta.appendChild(el("p", "az-sub", "Qué encontramos"));
      var lista = el("ul", "az-lista");
      for (i = 0; i < res.senales.length; i++) {
        var s = res.senales[i];
        li = el("li", "");
        li.appendChild(el("strong", "", s.etiqueta));
        li.appendChild(el("span", "az-det", s.detalle));
        if (s.evidencia && s.evidencia.length) {
          var partes = [];
          for (j = 0; j < s.evidencia.length; j++) { partes.push("“" + s.evidencia[j] + "”"); }
          li.appendChild(el("span", "az-ev", "Detectado: " + partes.join(", ")));
        }
        lista.appendChild(li);
      }
      tarjeta.appendChild(lista);
    }

    if (res.enlaces.length) {
      tarjeta.appendChild(el("p", "az-sub", "Enlaces que aparecen en el mensaje"));
      var enlaces = el("ul", "az-lista");
      for (i = 0; i < res.enlaces.length; i++) {
        li = el("li", "");
        li.appendChild(el("span", "az-ev", res.enlaces[i].url));
        li.appendChild(el("span", "az-det", "Sitio al que lleva: " + res.enlaces[i].host));
        enlaces.appendChild(li);
      }
      tarjeta.appendChild(enlaces);
    }

    if (res.consejos.length) {
      tarjeta.appendChild(el("p", "az-sub", "Qué hacer"));
      var pasos = el("ul", "az-lista");
      for (i = 0; i < res.consejos.length; i++) { pasos.appendChild(el("li", "", res.consejos[i])); }
      tarjeta.appendChild(pasos);
    }

    salida.appendChild(tarjeta);
    try {
      titulo.focus();
      if (salida.scrollIntoView) { salida.scrollIntoView(); }
    } catch (e) { /* navegadores viejos: no pasa nada */ }
  }

  function analizar() {
    var texto = campo.value;
    if (!texto || !/\S/.test(texto)) {
      mostrarAviso("Pegá primero el mensaje que querés revisar.");
      return;
    }
    dibujar(motor.analizar(texto));
  }

  function agregarEjemplo(ej) {
    var b = el("button", "az-btn", ej.titulo);
    b.type = "button";
    b.addEventListener("click", function () {
      campo.value = ej.texto;
      analizar();
    });
    ejemplos.appendChild(b);
  }

  var lista = window.REGLAS_ESTAFAS.ejemplos || [];
  for (var k = 0; k < lista.length; k++) { agregarEjemplo(lista[k]); }

  btnAnalizar.addEventListener("click", analizar);
  btnLimpiar.addEventListener("click", function () {
    campo.value = "";
    vaciar(salida);
    campo.focus();
  });

  var cargando = contenedor.querySelector(".az-cargando");
  if (cargando && cargando.parentNode) { cargando.parentNode.removeChild(cargando); }
  contenedor.className += " listo";
})();
