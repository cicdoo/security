import ipaddress
import logging

from odoo import models
from odoo.http import request, root, SessionExpiredException

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


def _legacy_key(value, mode):
    """Convert a pre-dual-stack ``bound_ip`` value to ``(family, key)``.

    Legacy subnet mode stored CIDRs (``10.1.2.0/24``); these keep their family.
    Returns ``None`` when the value cannot be carried over safely (the family
    then simply binds on the next request).
    """
    value = str(value)
    if '/' in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        if net.version == 6:
            return 'v6', str(ipaddress.ip_network(f'{net.network_address}/64', strict=False))
        if mode == 'subnet' and net.prefixlen == 24:
            return 'v4', str(net)
        return None
    return _network_key(value, mode)


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
        if icp.get_param('session_ip_binding.enabled', 'True').strip().lower() != 'true':
            return
        mode = icp.get_param('session_ip_binding.mode', 'exact')
        session = request.session
        family, ip = _network_key(request.httprequest.remote_addr or '', mode)
        # migrate sessions bound before per-family binding existed
        legacy = session.pop('bound_ip', None)
        if legacy is not None:
            migrated = _legacy_key(legacy, mode)
            if migrated:
                session.setdefault(f'bound_ip_{migrated[0]}', migrated[1])
        field = f'bound_ip_{family}'
        bound = session.get(field)
        if bound is None:
            session[field] = ip
            return
        if bound != ip:
            _logger.warning(
                "Session IP changed for user id %s (%s %s -> %s) on %s: session revoked",
                session.uid, family, bound, ip, request.httprequest.path)
            session.logout(keep_db=True)
            # drop the stored server-side session so the old cookie is dead
            root.session_store.rotate(session, request.env)
            raise SessionExpiredException("Session IP changed")
