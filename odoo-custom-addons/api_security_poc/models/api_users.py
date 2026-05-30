from odoo import models, fields, api
from passlib.context import CryptContext
import logging

_crypt_context = CryptContext(schemes=['pbkdf2_sha512'], deprecated='auto')

_logger = logging.getLogger(__name__)

class ApiUsuarios(models.Model):
    _name = 'x_api_usuarios'
    _description = 'Tabla de Usuarios Externos Protegida - Hardened 2026'

    name = fields.Char(string='Nombre Completo', required=True)
    login = fields.Char(string='Usuario/Email', required=True, index=True)
    password_hash = fields.Char(string='Hash de Password', required=True)
    
    # El switch de "muerte súbita" para Zero Trust
    active = fields.Boolean(string='Activo', default=True, help="Desactivar para revocar acceso inmediato")
    
    rol_seguridad = fields.Selection([
        ('admin-api', 'Administrador'),
        ('user-api', 'Usuario Estándar')
    ], default='user-api', string='Rol de Seguridad')

    @api.model
    def validate_external_credentials(self, username, password):
        """
        Valida credenciales para servicios externos (Node.js/Keycloak).
        No utiliza res.users para evitar exponer cuentas administrativas del ERP.
        """
        # 1. Búsqueda por login y estado activo (Principio de disponibilidad)
        user = self.search([
            ('login', '=', username),
            ('active', '=', True)
        ], limit=1)
        
        if not user:
            _logger.warning(f"AUTH_FAIL: Intento para {username} (Inexistente o Inactivo)")
            return {'status': 'error', 'message': 'Auth Failed'}

        # 2. Validación Criptográfica (Zero Trust: No confiamos en el texto plano)
        try:
            is_valid = _crypt_context.verify(password, user.password_hash)
            
            if is_valid:
                _logger.info(f"AUTH_SUCCESS: Usuario {username} validado via Identity Bridge")
                return {
                    'status': 'success',
                    'user_id': user.id,
                    'login': user.login,
                    'role': user.rol_seguridad,
                    'name': user.name
                }
            
            _logger.error(f"AUTH_INVALID: Password incorrecto para {username}")
            return {'status': 'error', 'message': 'Invalid Credentials'}

        except Exception as e:
            # Captura errores si el hash está corrupto o el algoritmo no es soportado
            _logger.critical(f"AUTH_CRITICAL: Error en motor de hash para {username}: {str(e)}")
            return {'status': 'error', 'message': 'Internal Security Error'}