from unittest.mock import MagicMock, patch

from odoo.http.session import SessionExpiredException
from odoo.tests.common import TransactionCase, tagged

from odoo.addons.session_ip_binding.models import ir_http
from odoo.addons.session_ip_binding.models.ir_http import IrHttp, _network_key


class FakeSession(dict):
    uid = 7


@tagged('post_install', '-at_install')
class TestIpBinding(TransactionCase):

    def _req(self, session, ip):
        req = MagicMock()
        req.session = session
        req.env = self.env
        req.httprequest.remote_addr = ip
        req.httprequest.path = '/x'
        with patch.object(ir_http, 'request', req), \
                patch.object(ir_http, 'logout'), \
                patch.object(ir_http, 'session_store'):
            IrHttp._check_session_ip()

    def test_key(self):
        self.assertEqual(_network_key('1.2.3.4', 'exact'), ('v4', '1.2.3.4'))
        self.assertEqual(_network_key('1.2.3.4', 'subnet'), ('v4', '1.2.3.0/24'))
        self.assertEqual(_network_key('::ffff:1.2.3.4', 'exact'), ('v4', '1.2.3.4'))
        self.assertEqual(_network_key('2001:db8:1:2:3:4:5:6', 'exact'),
                         ('v6', '2001:db8:1:2::/64'))
        self.assertEqual(_network_key('junk', 'exact'), ('raw', 'junk'))

    def test_family_switch_ok(self):
        s = FakeSession()
        for ip in ('1.2.3.4', '2001:db8::1', '1.2.3.4', '2001:db8::2'):
            self._req(s, ip)

    def test_v4_change_revokes(self):
        s = FakeSession()
        self._req(s, '1.2.3.4')
        with self.assertRaises(SessionExpiredException):
            self._req(s, '1.2.3.5')

    def test_v6_prefix(self):
        s = FakeSession()
        self._req(s, '2001:db8:1:2::1')
        self._req(s, '2001:db8:1:2::ffff')
        with self.assertRaises(SessionExpiredException):
            self._req(s, '2001:db8:1:3::1')

    def test_legacy_migration(self):
        s = FakeSession(bound_ip='1.2.3.4')
        self._req(s, '1.2.3.4')
        self.assertNotIn('bound_ip', s)
        self.assertEqual(s['bound_ip_v4'], '1.2.3.4')
        s = FakeSession(bound_ip='2001:db8:1:2::1')
        self._req(s, '2001:db8:1:2::9')
        self.assertEqual(s['bound_ip_v6'], '2001:db8:1:2::/64')

    def test_mapped_is_v4(self):
        s = FakeSession()
        self._req(s, '1.2.3.4')
        self._req(s, '::ffff:1.2.3.4')
        with self.assertRaises(SessionExpiredException):
            self._req(s, '::ffff:1.2.3.9')

    def test_subnet_mode(self):
        self.env['ir.config_parameter'].set_str('session_ip_binding.mode', 'subnet')
        s = FakeSession()
        self._req(s, '1.2.3.4')
        self._req(s, '1.2.3.99')
        with self.assertRaises(SessionExpiredException):
            self._req(s, '1.2.4.1')

    def test_disabled(self):
        self.env['ir.config_parameter'].set_bool('session_ip_binding.enabled', False)
        s = FakeSession()
        self._req(s, '1.2.3.4')
        self._req(s, '5.6.7.8')
        self.assertEqual(s, {})
