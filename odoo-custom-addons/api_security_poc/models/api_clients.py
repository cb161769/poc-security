from odoo import models, fields, api
import logging

_logger = logging.getLogger(__name__)


class ApiClientes(models.Model):
    _name = 'x_api_clientes'
    _description = 'Clientes JWT Autorizados'

    name = fields.Char(string='Nombre', required=True)
    sub = fields.Char(string='JWT Subject (sub)', index=True)
    email = fields.Char(string='Email', index=True)
    client_id = fields.Char(string='OAuth Client ID (azp)')
    active = fields.Boolean(default=True)
    roles_permitidos = fields.Char(
        string='Roles Permitidos',
        help='Roles separados por coma. Vacío = acepta cualquier rol.'
    )

    @api.model
    def validate_jwt_client(self, claims):
        """
        Valida que el portador del JWT esté autorizado a nivel de negocio.
        Recibe: { sub, email, client_id, roles }
        Retorna: { authorized: True, client: {...} } o { authorized: False }
        """
        sub = claims.get('sub')
        email = claims.get('email')
        client_id = claims.get('client_id')
        roles = claims.get('roles', [])

        domain = [('active', '=', True)]
        if sub:
            domain.append(('sub', '=', sub))
        elif email:
            domain.append(('email', '=', email))
        else:
            _logger.warning('JWT_AUTHZ: claims sin sub ni email')
            return {'authorized': False}

        cliente = self.search(domain, limit=1)

        if not cliente:
            _logger.warning(f'JWT_AUTHZ: No autorizado — sub={sub} email={email}')
            return {'authorized': False}

        # Validación de roles si el registro los restringe
        if cliente.roles_permitidos:
            permitidos = {r.strip() for r in cliente.roles_permitidos.split(',')}
            if not permitidos.intersection(set(roles)):
                _logger.warning(f'JWT_AUTHZ: Roles insuficientes para sub={sub}')
                return {'authorized': False}

        _logger.info(f'JWT_AUTHZ: Acceso concedido a sub={sub}')
        return {
            'authorized': True,
            'client': {
                'id': cliente.id,
                'name': cliente.name,
                'email': cliente.email,
                'client_id': cliente.client_id,
            },
        }
