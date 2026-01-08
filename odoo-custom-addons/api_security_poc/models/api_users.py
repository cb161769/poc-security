from odoo import models, fields, api
from odoo.exceptions import AccessError
import logging

_logger = logging.getLogger(__name__)

class ApiUsuarios(models.Model):
    _name = 'x_api_usuarios'
    _description = 'Tabla de Usuarios Externos Protegida'

    name = fields.Char(string='Nombre Completo', required=True)
    login = fields.Char(string='Usuario/Email', required=True, index=True)
    password_hash = fields.Char(string='Hash de Password', required=True)
    rol_seguridad = fields.Selection([
        ('admin-api', 'Administrador'),
        ('user-api', 'Usuario Estándar')
    ], default='user-api')

    @api.model
    def validate_external_credentials(self, username, password):
        """
        Método llamado por el Auth-Proxy de Node.js.
        Valida el password usando el motor de hashing de Odoo.
        """
        # 1. Buscar el usuario en la tabla personalizada
        user = self.search([('login', '=', username)], limit=1)
        
        if not user:
            _logger.warning(f"Seguridad 2026: Intento de acceso fallido para {username}")
            return {'status': 'error', 'message': 'Usuario no encontrado'}

        # 2. Validar password usando el motor nativo de Odoo (PBKDF2/SHA512)
        try:
            # Comparamos el password recibido con el hash guardado
            self.env['res.users']._check_credentials(user.password_hash, password)
            
            _logger.info(f"Seguridad 2026: Usuario {username} validado correctamente")
            return {
                'status': 'success',
                'user_id': user.id,
                'role': user.rol_seguridad
            }
        except AccessError:
            _logger.error(f"Seguridad 2026: Password incorrecto para {username}")
            return {'status': 'error', 'message': 'Credenciales inválidas'}
