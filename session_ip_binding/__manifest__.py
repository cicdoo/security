{
    'name': 'Session IP binding',
    'version': '19.0.1.0.0',
    'summary': 'Revoke sessions when the client IP / network changes',
    'author': 'CICDoo',
    'license': 'LGPL-3',
    'depends': ['base', 'web', 'base_setup'],
    'data': [
        'data/ir_config_parameter.xml',
        'views/res_config_settings_views.xml',
    ],
    'installable': True,
}
