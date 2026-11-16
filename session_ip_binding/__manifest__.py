{
    'name': 'Session IP binding',
    'version': '20.0.1.1.0',
    'summary': 'Revoke sessions when the client IP / network changes',
    'author': 'CICDoo',
    'license': 'LGPL-3',
    'depends': ['base', 'web'],
    'data': [
        'data/ir_config_parameter.xml',
        'views/res_config_settings_views.xml',
    ],
    'installable': True,
}
