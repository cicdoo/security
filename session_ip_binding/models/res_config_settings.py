from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    session_ip_binding_enabled = fields.Boolean(
        string="Bind sessions to client IP",
        config_parameter='session_ip_binding.enabled', default=True)
    session_ip_binding_mode = fields.Selection(
        [('exact', 'Exact IPv4, /64 IPv6'), ('subnet', 'IPv4 /24, /64 IPv6')],
        string="IP match mode",
        config_parameter='session_ip_binding.mode', default='exact')
