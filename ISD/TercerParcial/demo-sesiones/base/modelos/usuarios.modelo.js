// Consultas a la tabla usuarios. Siempre con ? (consulta parametrizada), nunca pegando texto en el SQL.
const bcrypt = require('bcryptjs');

function crearModeloUsuarios(pool) {
  async function verificar(usuarioInput, contrasenaInput) {
    const [filas] = await pool.query(
      'SELECT * FROM usuarios WHERE usuario = ?',
      [usuarioInput]
    );

    if (filas.length === 0) return null;

    const usuario = filas[0];
    
    // Usamos el nombre exacto de la columna que arroja tu tabla
    const passwordGuardada = usuario.contrasena_hash;
    
    if (!passwordGuardada) return null;

    let passwordValida = false;
    if (passwordGuardada.startsWith('$2')) {
      passwordValida = await bcrypt.compare(contrasenaInput, passwordGuardada);
    } else {
      passwordValida = (passwordGuardada === contrasenaInput);
    }

    if (!passwordValida) return null;

    // Retornamos los datos eliminando el hash por seguridad
    const { contrasena_hash, ...datosUsuario } = usuario;
    return datosUsuario;
  }

  return { verificar };
}

module.exports = { crearModeloUsuarios };