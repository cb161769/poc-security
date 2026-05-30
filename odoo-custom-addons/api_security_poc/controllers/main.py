import os
import json
from odoo import http
from odoo.http import request, Response


class ApiSecurityController(http.Controller):

    @http.route(
        '/api/validate-jwt-client',
        type='http',
        auth='public',
        methods=['POST'],
        csrf=False,
    )
    def validate_jwt_client(self, **kwargs):
        expected = os.environ.get('INTERNAL_SECRET', '')
        received = request.httprequest.headers.get('X-Internal-Secret', '')
        if not expected or received != expected:
            return Response(json.dumps({'authorized': False}), mimetype='application/json', status=401)

        try:
            claims = json.loads(request.httprequest.data)
        except Exception:
            return Response(json.dumps({'authorized': False}), mimetype='application/json', status=400)

        result = request.env['x_api_clientes'].sudo().validate_jwt_client(claims)
        return Response(json.dumps(result), mimetype='application/json')
