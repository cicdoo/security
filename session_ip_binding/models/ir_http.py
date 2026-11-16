import ipaddress
import logging

from odoo import models
from odoo.http import SessionExpiredException, request, root

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


def _param_enabled(value):
    return (value or '') not in ('False', 'false', '0', '')


class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _authenticate_explicit(cls, auth):
        super()._authenticate_explicit(auth)
        if request.session.uid:
            cls._check_session_ip()

    @classmethod
    def _check_session_ip(cls):
        icp = request.env['ir.config_parameter'].sudo()
        if not _param_enabled(icp.get_param('session_ip_binding.enabled', 'True')):
            return
        mode = icp.get_param('session_ip_binding.mode', 'exact')
        session = request.session
        ip = _network_key(request.httprequest.remote_addr or '', mode)
        bound = session.get('bound_ip')
        if bound is None:
            session['bound_ip'] = ip
            return
        if bound != ip:
            uid = session.uid
            _logger.warning(
                "Session IP changed for user id %s (%s -> %s) on %s: session revoked",
                uid, bound, ip, request.httprequest.path)
            session.logout(keep_db=True)
            # drop the stored server-side session so the old cookie is dead
            root.session_store.rotate(session, request.env)
            raise SessionExpiredException("Session IP changed")
