import ipaddress
import logging

from odoo import models
from odoo.http import SessionExpiredException, request

_logger = logging.getLogger(__name__)


def _network_key(ip, mode):
    if mode != 'subnet':
        return ip
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f'{ip}/{prefix}', strict=False))


class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _authenticate(cls, endpoint):
        super()._authenticate(endpoint)
        if request.session.uid:
            cls._check_session_ip()

    @classmethod
    def _check_session_ip(cls):
        icp = request.env['ir.config_parameter'].sudo()
        if icp.get_param('session_ip_binding.enabled', 'True') == 'False':
            return
        mode = icp.get_param('session_ip_binding.mode', 'exact')
        session = request.session
        ip = _network_key(request.httprequest.remote_addr or '', mode)
        bound = session.get('bound_ip')
        if bound is None:
            session['bound_ip'] = ip
            return
        if bound != ip:
            _logger.warning(
                "Session IP changed for user id %s (%s -> %s) on %s: session revoked",
                session.uid, bound, ip, request.httprequest.path)
            session.logout(keep_db=True)
            raise SessionExpiredException("Session IP changed")
