const express = require('express');
const axios = require('axios');
const app = express();

app.use(express.json());

const ODOO_URL = process.env.ODOO_URL || 'http://odoo-server:8069';

// Middleware para verificar que la petición viene de nuestro Kong
app.use((req, res, next) => {
    const userSub = req.header('X-User-Sub');
    if (!userSub) {
        return res.status(403).json({ error: 'Acceso denegado: No identificado por Gateway' });
    }
    next();
});

// Endpoint de prueba para tu App Mobile/Web
app.get('/api/v1/data', async (req, res) => {
    const userRole = req.header('X-User-Role');
    
    console.log(`Petición recibida del usuario: ${req.header('X-User-Email')}`);

    res.json({
        message: "Datos protegidos por JOSE/JWE recuperados con éxito",
        timestamp: new Date().toISOString(),
        permissions: userRole
    });
});

// Endpoint que Keycloak usará para validar contra Odoo
app.post('/internal/validate-user', async (req, res) => {
    const { username, password } = req.body;

    try {
        const response = await axios.post(`${ODOO_URL}/jsonrpc`, {
            jsonrpc: "2.0",
            method: "call",
            params: {
                model: "x_api_usuarios",
                method: "validate_external_credentials",
                args: [username, password]
            }
        });

        if (response.data.result && response.data.result.status === 'success') {
            res.json(response.data.result);
        } else {
            res.status(401).json({ status: 'error', message: 'Credenciales inválidas en Odoo' });
        }
    } catch (error) {
        res.status(500).json({ status: 'error', message: 'Error de conexión con Odoo' });
    }
});

app.listen(3000, () => {
    console.log('Backend API & Identity Bridge funcionando en puerto 3000');
});