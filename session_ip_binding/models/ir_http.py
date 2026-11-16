import ipaddress
import logging

from odoo import models
from odoo.http import request
from odoo.http.session import SessionExpiredException, logout, session_store

_logger = logging.getLogger(__name__)


def _network_key(ip, mode):
    """Return ``(family, key)`` for a client IP.

    family is 'v4', 'v6' or 'raw' (unparseable). IPv4-mapped IPv6 addresses
    count as IPv4. IPv6 is always reduced to its /64; IPv4 to its /24 only in
    ``subnet`` mode.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return 'raw', ip
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.version == 6:
        return 'v6', str(ipaddress.ip_network(f'{addr}/64', strict=False))
    if mode == 'subnet':
        return 'v4', str(ipaddress.ip_network(f'{addr}/24', strict=False))
    return 'v4', str(addr)


class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _authenticate_explicit(cls, routing):
        super()._authenticate_explicit(routing)
        if request.session.uid:
            cls._check_session_ip()

    @classmethod
    def _check_session_ip(cls):
        icp = request.env['ir.config_parameter'].sudo()
        if not icp.get_bool('session_ip_binding.enabled', True):
            return
        mode = icp.get_str('session_ip_binding.mode', 'exact')
        session = request.session
        family, ip = _network_key(request.httprequest.remote_addr or '', mode)
        # migrate sessions bound before per-family binding existed
        legacy = session.pop('bound_ip', None)
        if legacy is not None:
            lfam, lkey = _network_key(legacy, mode)
            session.setdefault(f'bound_ip_{lfam}', lkey)
        field = f'bound_ip_{family}'
        bound = session.get(field)
        if bound is None:
            session[field] = ip
            return
        if bound != ip:
            _logger.warning(
                "Session IP changed for user id %s (%s %s -> %s) on %s: session revoked",
                session.uid, family, bound, ip, request.httprequest.path)
            logout(session, keep_db=True)
            # drop the stored server-side session so the old cookie is dead
            session_store().rotate(session, request.env)
            raise SessionExpiredException("Session IP changed")
