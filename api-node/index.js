const express = require('express');
const app = express();
app.use(express.json());

app.post('/execute', (req, res) => {
  const userEmail = req.headers['x-user-email'];
  const userRoles = req.headers['x-user-roles'] || "";
  const data = req.body ?? {}; // Kong ya lo desencriptó

  console.log(`[Seguridad 2026] Petición de: ${userEmail} con roles: ${userRoles}`);

  // Validación de Rol Administrativo
  if (!userRoles.includes('admin-api')) {
    return res.status(403).json({ error: "Acceso denegado: Se requiere rol admin-api" });
  }

  res.json({
    status: "Éxito",
    message: "Cuerpo JWE desencriptado y Rol validado",
    recibido: data
  });
});

app.listen(3000, () => console.log('🚀 Backend escuchando en puerto 3000'));