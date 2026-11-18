// La página solo hace fetch a la API. El navegador manda la cookie sola (misma página, mismo servidor).
const $ = (id) => document.getElementById(id);

/*
 * Qué hace: Ejecuta peticiones HTTP (GET, POST, etc.) hacia la API usando fetch, serializa el cuerpo a JSON si existe y devuelve un objeto { status, datos }.
 * Por qué: Centraliza la comunicación con el servidor para no repetir la configuración del encabezado 'Content-Type: application/json' (necesario para que express.json() lea el body) y envuelve el parseo en un try/catch para que, si el servidor responde con algo que no sea JSON válido (como un error HTML inesperado), la aplicación devuelva null en lugar de detenerse con una excepción. Además, no requiere credentials: 'include' porque el frontend y el backend comparten el mismo origen (host y puerto).
 */
async function llamar(metodo, url, cuerpo) {
  const opciones = { method: metodo, headers: {} };
  if (cuerpo) {
    opciones.headers['Content-Type'] = 'application/json';
    opciones.body = JSON.stringify(cuerpo);
  }
  const respuesta = await fetch(url, opciones);
  let datos = null;
  try { datos = await respuesta.json(); } catch { datos = null; }
  return { status: respuesta.status, datos };
}

/*
 * Qué hace: Crea un elemento de lista (<li>) con el código de estado HTTP coloreado según su rango (2xx, 401, 403 u otro), la ruta consultada y el JSON formateado dentro de un <pre>, insertándolo al inicio de #bitacora.
 * Por qué: Permite auditar cronológicamente (con lo más reciente arriba mediante prepend) cada respuesta de la API. Utiliza textContent en lugar de innerHTML para volcar los datos provenientes del servidor con el fin de mitigar ataques XSS (Cross-Site Scripting), evitando que cualquier cadena maliciosa se interprete como HTML ejecutable.
 */
function anotar(metodo, url, status, datos) {
  const li = document.createElement('li');
  const clase = status < 300 ? 'ok' : status === 401 ? 'e401' : status === 403 ? 'e403' : 'error';
  li.innerHTML = `<span class="codigo ${clase}">${status}</span> <code>${metodo} ${url}</code>`;
  const cuerpo = document.createElement('pre');
  cuerpo.textContent = JSON.stringify(datos, null, 2);
  li.appendChild(cuerpo);
  $('bitacora').prepend(li);
}

/*
 * Qué hace: Consulta GET /api/sesion para actualizar el indicador superior (#estado) con los datos del usuario activo o el aviso de falta de sesión, y muestra el contenido de document.cookie en #cookie-js.
 * Por qué: Mantiene sincronizada la interfaz con el estado real de autenticación en el servidor (ya que fetch no lanza errores automáticos ante códigos 401/403) y permite comprobar visualmente el efecto de la bandera httpOnly: cuando está en true, document.cookie aparece vacío aunque exista una sesión válida, demostrando que JavaScript no puede leer ni robar la cookie.
 */
async function refrescarEstado() {
  const { status, datos } = await llamar('GET', '/api/sesion');
  const estado = $('estado');
  if (status === 200) {
    estado.textContent = `${datos.usuario.nombre} · rol ${datos.usuario.rol} · sesión ${datos.sesion} · vence en ${datos.expiraEnSegundos} s`;
    estado.className = 'estado con-sesion';
  } else {
    estado.textContent = 'Sin sesión (el servidor responde 401)';
    estado.className = 'estado sin-sesion';
  }
  $('cookie-js').textContent = document.cookie || '(vacío)';
}

/*
 * Qué hace: Consulta GET /api/diagnostico/sesiones, indica si el almacenamiento activo es memoria RAM o MySQL (#donde) y reconstruye las filas de #tabla-sesiones resaltando la sesión actual y formateando la fecha de expiración.
 * Por qué: Permite inspeccionar en tiempo real cómo persiste el servidor las sesiones activas y distinguir la sesión propia mediante la clase CSS 'tuya'. Limpia previamente el <tbody> (cuerpo.innerHTML = '') para evitar que las filas se dupliquen al refrescar, transforma la fecha ISO a hora local legible con toLocaleTimeString() y usa textContent en cada celda para garantizar seguridad contra inyección de HTML.
 */
async function refrescarSesiones() {
  const { datos: respuesta } = await llamar('GET', '/api/diagnostico/sesiones');
  const datos = respuesta ? respuesta.sesiones : [];
  if (respuesta) {
    $('donde').textContent = respuesta.almacen === 'memoria'
      ? 'En la MEMORIA del servidor: se borra al reiniciarlo.'
      : 'En MySQL, tabla sessions. En Workbench: SELECT * FROM demo_sesiones.sessions;';
  }
  const cuerpo = $('tabla-sesiones');
  cuerpo.innerHTML = '';
  if (!datos || datos.length === 0) {
    cuerpo.innerHTML = '<tr><td colspan="4">(sin sesiones)</td></tr>';
    return;
  }
  for (const s of datos) {
    const fila = document.createElement('tr');
    if (s.esLaTuya) fila.className = 'tuya';
    const vence = s.expira ? new Date(s.expira).toLocaleTimeString() : '—';
    for (const valor of [s.sesion + (s.esLaTuya ? ' (la tuya)' : ''), s.usuario, s.visitas, vence]) {
      const celda = document.createElement('td');
      celda.textContent = valor;
      fila.appendChild(celda);
    }
    cuerpo.appendChild(fila);
  }
}

/*
 * Qué hace: Ejecuta secuencialmente refrescarEstado() y refrescarSesiones().
 * Por qué: Evita duplicar ambas llamadas en cada evento (login, logout, visitas o rutas protegidas), asegurando que tanto el banner superior como la tabla del servidor se mantengan coherentes después de cualquier operación que pueda crear, modificar o destruir una sesión.
 */
async function refrescarTodo() {
  await refrescarEstado();
  await refrescarSesiones();
}

// Qué hace: Actualiza el campo #contrasena automáticamente al cambiar la opción seleccionada en #usuario.
// Por qué: Agiliza las pruebas manuales de inicio de sesión siguiendo el patrón de credenciales de ejemplo (<usuario>12345) definido en la base de datos.
$('usuario').addEventListener('change', () => {
  $('contrasena').value = `${$('usuario').value}12345`;
});

// Qué hace: Intercepta el envío de #form-login, envía las credenciales mediante POST /api/login, registra el resultado y refresca la interfaz.
// Por qué: Llama a evento.preventDefault() para evitar la recarga tradicional de la página HTML, permitiendo gestionar el inicio de sesión de forma asíncrona (AJAX) y conservar visible la bitácora de respuestas.
$('form-login').addEventListener('submit', async (evento) => {
  evento.preventDefault();
  const cuerpo = { usuario: $('usuario').value, contrasena: $('contrasena').value };
  const { status, datos } = await llamar('POST', '/api/login', cuerpo);
  anotar('POST', '/api/login', status, datos);
  await refrescarTodo();
});

// Qué hace: Recorre todos los botones con el atributo data-url y les asigna un manejador de clic que lee boton.dataset (metodo y url) para invocar la API.
// Por qué: Evita escribir un addEventListener individual por cada botón de prueba en index.html, logrando un código escalable y desacoplado donde las rutas y métodos HTTP se definen directamente en el marcado HTML.
for (const boton of document.querySelectorAll('[data-url]')) {
  boton.addEventListener('click', async () => {
    const { metodo, url } = boton.dataset;
    const { status, datos } = await llamar(metodo, url);
    anotar(metodo, url, status, datos);
    await refrescarTodo();
  });
}

// Qué hace: Vincula los botones de actualización manual (#btn-refrescar y #btn-sesiones) con sus respectivas funciones de consulta.
// Por qué: Permite verificar cambios ocurridos en el servidor (como el vencimiento de una sesión por tiempo o reinicios del servidor) sin necesidad de disparar nuevas acciones de escritura o autenticación.
$('btn-refrescar').addEventListener('click', refrescarTodo);
$('btn-sesiones').addEventListener('click', refrescarSesiones);

// Qué hace: Solicita GET /api/config para mostrar los parámetros activos del servidor en #config y ejecuta la primera sincronización con refrescarTodo().
// Por qué: Inicializa la vista nada más cargar el script sin necesidad de esperar al evento DOMContentLoaded, ya que la etiqueta <script> se encuentra ubicada al final del <body> cuando todo el DOM ya fue construido.
llamar('GET', '/api/config').then(({ datos }) => {
  $('config').textContent = JSON.stringify(datos, null, 2);
});
refrescarTodo();