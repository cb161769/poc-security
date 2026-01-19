{
    'name': 'API Security POC 2026',
    'version': '1.0',
    'summary': 'Gestión de usuarios externos para JWE/JWT',
    'category': 'Tools',
    'author': 'Analista de Seguridad',
    'depends': ['base'],
    'data': [
        'security/ir.model.access.csv',
        'data/x_api_usuarios.csv',
    ],
    'installable': True,
    'application': True,
}
